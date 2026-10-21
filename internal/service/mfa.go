package service

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

func (s *Service) factor(ctx context.Context, tx pgx.Tx, u identity, code, recovery string) (bool, error) {
	if recovery != "" {
		tag, e := tx.Exec(ctx, "DELETE FROM auth_recovery WHERE user_id=$1 AND hash=$2", u.ID, digest(recovery))
		return tag.RowsAffected() == 1, e
	}
	secret, e := s.Config.decrypt(u.Secret)
	if e != nil {
		return false, e
	}
	return verifyTOTP(ctx, tx, u.ID, secret, code)
}
func verifyTOTP(ctx context.Context, tx pgx.Tx, id, secret, code string) (bool, error) {
	if len(code) != 6 {
		return false, nil
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false, nil
		}
	}
	for _, delta := range []int64{0, -1, 1} {
		at := time.Now().Add(time.Duration(delta) * 30 * time.Second)
		valid, e := totp.ValidateCustom(code, secret, at, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if e != nil {
			return false, e
		}
		if valid {
			step := at.Unix() / 30
			tag, e := tx.Exec(ctx, "UPDATE auth_users SET last_totp_step=$1 WHERE id=$2 AND last_totp_step<$1", step, id)
			return tag.RowsAffected() == 1, e
		}
	}
	return false, nil
}
func (s *Service) verifyMFA(w http.ResponseWriter, r *http.Request) (any, error) {
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	id, e := s.grantUser(r.Context(), q.Token, "mfa")
	if e != nil {
		return nil, e
	}
	return transact(r.Context(), s.DB, func(tx pgx.Tx) (any, error) {
		u, e := lockUser(r.Context(), tx, id)
		if e != nil {
			return nil, e
		}
		if !valid(u) || u.Secret == "" {
			return nil, denied
		}
		tag, e := tx.Exec(r.Context(), "UPDATE auth_grants SET attempts=attempts+1 WHERE hash=$1 AND user_id=$2 AND kind='mfa' AND version=$3 AND expires>clock_timestamp() AND attempts<5", digest(q.Token), u.ID, u.Version)
		if e != nil {
			return nil, e
		}
		if tag.RowsAffected() != 1 {
			return nil, denied
		}
		ok, e := s.factor(r.Context(), tx, u, q.Code, q.RecoveryCode)
		if e != nil {
			return nil, e
		}
		if !ok {
			return committedRejection{denied}, nil
		}
		// The fifth allowed attempt may succeed; consume has its own limit check.
		if _, e = tx.Exec(r.Context(), "DELETE FROM auth_grants WHERE hash=$1", digest(q.Token)); e != nil {
			return nil, e
		}
		return s.issue(r.Context(), tx, u, "")
	})
}
func (s *Service) stepup(w http.ResponseWriter, r *http.Request) (any, error) {
	p, e := s.authenticate(r)
	if e != nil {
		return nil, e
	}
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	if e = s.limit(r.Context(), "stepup:"+p.ID, 10); e != nil {
		return nil, e
	}
	return transact(r.Context(), s.DB, func(tx pgx.Tx) (any, error) {
		u, e := lockUser(r.Context(), tx, p.ID)
		if e != nil {
			return nil, e
		}
		if !valid(u) || u.Version != p.Version {
			return nil, denied
		}
		if e = activeSession(r.Context(), tx, p); e != nil {
			return nil, e
		}
		if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(q.Password)) != nil {
			return nil, denied
		}
		if u.Secret != "" {
			ok, e := s.factor(r.Context(), tx, u, q.Code, q.RecoveryCode)
			if e != nil {
				return nil, e
			}
			if !ok {
				return nil, denied
			}
		}
		token, e := grant(r.Context(), tx, u, "stepup", 5*time.Minute)
		if e != nil {
			return nil, e
		}
		if _, e = tx.Exec(r.Context(), "UPDATE auth_grants SET session_id=$1 WHERE hash=$2", p.Session, digest(token)); e != nil {
			return nil, e
		}
		return map[string]any{"proof": token, "expires_in": 300}, audit(r.Context(), tx, u, "stepup", u.ID)
	})
}
func (s *Service) setupMFA(w http.ResponseWriter, r *http.Request) (any, error) {
	p, e := s.authenticate(r)
	if e != nil {
		return nil, e
	}
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	key, e := totp.Generate(totp.GenerateOpts{Issuer: "NVUTO Auth", AccountName: p.Email, SecretSize: 20})
	if e != nil {
		return nil, e
	}
	encrypted, e := s.Config.encrypt(key.Secret())
	if e != nil {
		return nil, e
	}
	token := randomToken()
	return s.sensitive(r, p, q.Proof, func(tx pgx.Tx, u identity) (any, error) {
		_, e := tx.Exec(r.Context(), "UPDATE auth_users SET pending_secret=$1,pending_expires=clock_timestamp()+interval '10 minutes',pending_version=version,pending_token=$2,pending_attempts=0 WHERE id=$3", encrypted, digest(token), u.ID)
		if e != nil {
			return nil, e
		}
		return map[string]any{"secret": key.Secret(), "otpauth_url": key.URL(), "enrollment_token": token, "expires_in": 600}, audit(r.Context(), tx, u, "mfa_setup_started", u.ID)
	})
}
func (s *Service) confirmMFA(w http.ResponseWriter, r *http.Request) (any, error) {
	p, e := s.authenticate(r)
	if e != nil {
		return nil, e
	}
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	return transact(r.Context(), s.DB, func(tx pgx.Tx) (any, error) {
		u, e := lockUser(r.Context(), tx, p.ID)
		if e != nil {
			return nil, e
		}
		if !valid(u) || u.Version != p.Version {
			return nil, denied
		}
		if e = activeSession(r.Context(), tx, p); e != nil {
			return nil, e
		}
		var encrypted string
		e = tx.QueryRow(r.Context(), "UPDATE auth_users SET pending_attempts=pending_attempts+1 WHERE id=$1 AND pending_token=$2 AND pending_expires>clock_timestamp() AND pending_version=version AND pending_attempts<5 RETURNING pending_secret", u.ID, digest(q.Token)).Scan(&encrypted)
		if e != nil {
			return nil, denied
		}
		secret, e := s.Config.decrypt(encrypted)
		if e != nil {
			return nil, e
		}
		ok, e := verifyTOTP(r.Context(), tx, u.ID, secret, q.Code)
		if e != nil {
			return nil, e
		}
		if !ok {
			return committedRejection{denied}, nil
		}
		if _, e = tx.Exec(r.Context(), "UPDATE auth_users SET mfa_secret=$1,mfa_required=true WHERE id=$2", encrypted, u.ID); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(r.Context(), "DELETE FROM auth_recovery WHERE user_id=$1", u.ID); e != nil {
			return nil, e
		}
		codes := make([]string, 10)
		for i := range codes {
			codes[i] = randomToken()
			if _, e = tx.Exec(r.Context(), "INSERT INTO auth_recovery(user_id,hash) VALUES($1,$2)", u.ID, digest(codes[i])); e != nil {
				return nil, e
			}
		}
		if e = revoke(r.Context(), tx, u.ID); e != nil {
			return nil, e
		}
		if e = s.queue(r.Context(), tx, u, "security-notice", ""); e != nil {
			return nil, e
		}
		return map[string]any{"recovery_codes": codes, "message": "MFA enabled. Save these codes and sign in again."}, audit(r.Context(), tx, u, "mfa_enabled", u.ID)
	})
}
func (s *Service) disableMFA(w http.ResponseWriter, r *http.Request) (any, error) {
	p, e := s.authenticate(r)
	if e != nil {
		return nil, e
	}
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	return s.sensitive(r, p, q.Proof, func(tx pgx.Tx, u identity) (any, error) {
		if _, e := tx.Exec(r.Context(), "UPDATE auth_users SET mfa_secret=NULL,mfa_required=false,last_totp_step=-1 WHERE id=$1", u.ID); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(r.Context(), "DELETE FROM auth_recovery WHERE user_id=$1", u.ID); e != nil {
			return nil, e
		}
		if e = revoke(r.Context(), tx, u.ID); e != nil {
			return nil, e
		}
		if e = s.queue(r.Context(), tx, u, "security-notice", ""); e != nil {
			return nil, e
		}
		return map[string]string{"message": "MFA disabled. Sign in again."}, audit(r.Context(), tx, u, "mfa_disabled", u.ID)
	})
}
