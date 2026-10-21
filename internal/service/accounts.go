package service

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

var accepted = map[string]string{"message": "If the account is eligible, an email will be sent."}

func (s *Service) accountLimit(r *http.Request, q request) error {
	return s.limit(r.Context(), "account:"+digest(strings.ToLower(q.Tenant)+":"+strings.ToLower(q.Email)), 20)
}
func (s *Service) lookup(ctx context.Context, tenant, email string) (identity, error) {
	return userRow(s.DB.QueryRow(ctx, "SELECT "+userColumns+" FROM auth_users u JOIN auth_tenants t ON t.id=u.tenant_id WHERE t.slug=$1 AND u.email=$2", tenant, strings.ToLower(strings.TrimSpace(email))))
}
func (s *Service) register(w http.ResponseWriter, r *http.Request) (any, error) {
	if !s.Config.Registration {
		return nil, forbidden
	}
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	if e = s.accountLimit(r, q); e != nil {
		return nil, e
	}
	email, e := normalizedEmail(q.Email)
	if e != nil {
		return nil, e
	}
	hash, e := hashPassword(q.Password)
	if e != nil {
		return nil, e
	}
	if utf8.RuneCountInString(q.Name) > 120 {
		return nil, bad("name_too_long")
	}
	return transact(r.Context(), s.DB, func(tx pgx.Tx) (any, error) {
		var tenant string
		if e := tx.QueryRow(r.Context(), "SELECT id FROM auth_tenants WHERE slug=$1 AND active FOR SHARE", q.Tenant).Scan(&tenant); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return accepted, nil
			}
			return nil, e
		}
		u := identity{ID: uuid.NewString(), Tenant: tenant, Email: email, Name: q.Name, Role: "member"}
		tag, e := tx.Exec(r.Context(), "INSERT INTO auth_users(id,tenant_id,email,name,password_hash,role) VALUES($1,$2,$3,$4,$5,'member') ON CONFLICT(tenant_id,email) DO NOTHING", u.ID, tenant, email, q.Name, hash)
		if e != nil {
			return nil, e
		}
		if tag.RowsAffected() == 0 {
			return accepted, nil
		}
		token, e := grant(r.Context(), tx, u, "verify", 24*time.Hour)
		if e != nil {
			return nil, e
		}
		if e = s.queue(r.Context(), tx, u, "verify", token); e != nil {
			return nil, e
		}
		return accepted, audit(r.Context(), tx, u, "registration", u.ID)
	})
}
func (s *Service) grantUser(ctx context.Context, raw, kind string) (string, error) {
	var id string
	e := s.DB.QueryRow(ctx, "SELECT user_id FROM auth_grants WHERE hash=$1 AND kind=$2 AND expires>clock_timestamp()", digest(raw), kind).Scan(&id)
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return "", denied
		}
		return "", e
	}
	return id, nil
}
func (s *Service) verifyEmail(w http.ResponseWriter, r *http.Request) (any, error) {
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	id, e := s.grantUser(r.Context(), q.Token, "verify")
	if e != nil {
		return nil, e
	}
	return transact(r.Context(), s.DB, func(tx pgx.Tx) (any, error) {
		u, e := lockUser(r.Context(), tx, id)
		if e != nil {
			return nil, e
		}
		if !u.Active || !u.TenantActive {
			return nil, denied
		}
		if e = consume(r.Context(), tx, u, "verify", q.Token); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(r.Context(), "UPDATE auth_users SET verified=true WHERE id=$1", u.ID); e != nil {
			return nil, e
		}
		return map[string]string{"message": "Email verified. Sign in to continue."}, audit(r.Context(), tx, u, "email_verified", u.ID)
	})
}
func (s *Service) resendVerification(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.emailGrant(r, "verify")
}
func (s *Service) forgot(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.emailGrant(r, "reset")
}
func (s *Service) emailGrant(r *http.Request, kind string) (any, error) {
	started := time.Now()
	defer func() {
		if wait := 250*time.Millisecond - time.Since(started); wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-r.Context().Done():
			case <-timer.C:
			}
		}
	}()
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	if e = s.accountLimit(r, q); e != nil {
		return nil, e
	}
	u, e := s.lookup(r.Context(), q.Tenant, q.Email)
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return accepted, nil
		}
		return nil, e
	}
	return transact(r.Context(), s.DB, func(tx pgx.Tx) (any, error) {
		u, e := lockUser(r.Context(), tx, u.ID)
		if e != nil {
			return nil, e
		}
		if !u.Active || !u.TenantActive || (kind == "verify" && u.Verified) || (kind == "reset" && !u.Verified) {
			return accepted, nil
		}
		if _, e = tx.Exec(r.Context(), "DELETE FROM auth_grants WHERE user_id=$1 AND kind=$2", u.ID, kind); e != nil {
			return nil, e
		}
		token, e := grant(r.Context(), tx, u, kind, 15*time.Minute)
		if e != nil {
			return nil, e
		}
		if e = s.queue(r.Context(), tx, u, kind, token); e != nil {
			return nil, e
		}
		return accepted, audit(r.Context(), tx, u, kind+"_requested", u.ID)
	})
}
func (s *Service) reset(w http.ResponseWriter, r *http.Request) (any, error) {
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	hash, e := hashPassword(q.NewPassword)
	if e != nil {
		return nil, e
	}
	id, e := s.grantUser(r.Context(), q.Token, "reset")
	if e != nil {
		return nil, e
	}
	return transact(r.Context(), s.DB, func(tx pgx.Tx) (any, error) {
		u, e := lockUser(r.Context(), tx, id)
		if e != nil {
			return nil, e
		}
		if !valid(u) {
			return nil, denied
		}
		if e = consume(r.Context(), tx, u, "reset", q.Token); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(r.Context(), "UPDATE auth_users SET password_hash=$1 WHERE id=$2", hash, u.ID); e != nil {
			return nil, e
		}
		if e = revoke(r.Context(), tx, u.ID); e != nil {
			return nil, e
		}
		if e = s.queue(r.Context(), tx, u, "security-notice", ""); e != nil {
			return nil, e
		}
		return map[string]string{"message": "Password reset. Sign in and complete enrolled MFA."}, audit(r.Context(), tx, u, "password_reset", u.ID)
	})
}
func (s *Service) login(w http.ResponseWriter, r *http.Request) (any, error) {
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	if e = s.accountLimit(r, q); e != nil {
		return nil, e
	}
	u, e := s.lookup(r.Context(), q.Tenant, q.Email)
	if e != nil {
		_ = bcrypt.CompareHashAndPassword(dummyPassword, []byte(q.Password))
		if errors.Is(e, pgx.ErrNoRows) {
			return nil, denied
		}
		return nil, e
	}
	if !valid(u) || u.Password == "!" {
		_ = bcrypt.CompareHashAndPassword(dummyPassword, []byte(q.Password))
		return nil, denied
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(q.Password)) != nil {
		return nil, denied
	}
	return transact(r.Context(), s.DB, func(tx pgx.Tx) (any, error) {
		current, e := lockUser(r.Context(), tx, u.ID)
		if e != nil {
			return nil, e
		}
		if !valid(current) || current.Version != u.Version || current.Password != u.Password {
			return nil, denied
		}
		if current.Secret != "" {
			token, e := grant(r.Context(), tx, current, "mfa", 5*time.Minute)
			return map[string]any{"mfa_required": true, "challenge": token, "expires_in": 300}, e
		}
		return s.issue(r.Context(), tx, current, "")
	})
}

var dummyPassword = func() []byte {
	b, e := bcrypt.GenerateFromPassword([]byte(randomToken()), 12)
	if e != nil {
		panic(e)
	}
	return b
}()

func (s *Service) me(w http.ResponseWriter, r *http.Request) (any, error) {
	p, e := s.authenticate(r)
	if e != nil {
		return nil, e
	}
	return safeUser(p.identity), nil
}
func (s *Service) changePassword(w http.ResponseWriter, r *http.Request) (any, error) {
	p, e := s.authenticate(r)
	if e != nil {
		return nil, e
	}
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	hash, e := hashPassword(q.NewPassword)
	if e != nil {
		return nil, e
	}
	return s.sensitive(r, p, q.Proof, func(tx pgx.Tx, u identity) (any, error) {
		if _, e := tx.Exec(r.Context(), "UPDATE auth_users SET password_hash=$1 WHERE id=$2", hash, u.ID); e != nil {
			return nil, e
		}
		if e = revoke(r.Context(), tx, u.ID); e != nil {
			return nil, e
		}
		if e = s.queue(r.Context(), tx, u, "security-notice", ""); e != nil {
			return nil, e
		}
		return map[string]string{"message": "Password changed. Sign in again."}, audit(r.Context(), tx, u, "password_changed", u.ID)
	})
}
func (s *Service) invite(w http.ResponseWriter, r *http.Request) (any, error) {
	p, e := s.authenticate(r)
	if e != nil {
		return nil, e
	}
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	email, e := normalizedEmail(q.Email)
	if e != nil {
		return nil, e
	}
	if utf8.RuneCountInString(q.Name) > 120 {
		return nil, bad("name_too_long")
	}
	return s.sensitive(r, p, q.Proof, func(tx pgx.Tx, actor identity) (any, error) {
		if actor.Role != "owner" {
			return nil, forbidden
		}
		u := identity{ID: uuid.NewString(), Tenant: actor.Tenant, Email: email, Name: q.Name, Role: "member"}
		tag, e := tx.Exec(r.Context(), "INSERT INTO auth_users(id,tenant_id,email,name,password_hash,role,active) VALUES($1,$2,$3,$4,'!','member',false) ON CONFLICT(tenant_id,email) DO NOTHING", u.ID, u.Tenant, email, q.Name)
		if e != nil {
			return nil, e
		}
		if tag.RowsAffected() != 1 {
			return nil, bad("account_already_exists")
		}
		token, e := grant(r.Context(), tx, u, "invite", 24*time.Hour)
		if e != nil {
			return nil, e
		}
		if e = s.queue(r.Context(), tx, u, "invite", token); e != nil {
			return nil, e
		}
		return map[string]string{"user_id": u.ID}, audit(r.Context(), tx, actor, "invited", u.ID)
	})
}
func (s *Service) acceptInvite(w http.ResponseWriter, r *http.Request) (any, error) {
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	hash, e := hashPassword(q.NewPassword)
	if e != nil {
		return nil, e
	}
	id, e := s.grantUser(r.Context(), q.Token, "invite")
	if e != nil {
		return nil, e
	}
	return transact(r.Context(), s.DB, func(tx pgx.Tx) (any, error) {
		u, e := lockUser(r.Context(), tx, id)
		if e != nil {
			return nil, e
		}
		if !u.TenantActive || u.Verified || u.Active {
			return nil, denied
		}
		if e = consume(r.Context(), tx, u, "invite", q.Token); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(r.Context(), "UPDATE auth_users SET active=true,verified=true,password_hash=$1 WHERE id=$2", hash, u.ID); e != nil {
			return nil, e
		}
		if e = revoke(r.Context(), tx, u.ID); e != nil {
			return nil, e
		}
		return map[string]string{"message": "Invitation accepted. Sign in to continue."}, audit(r.Context(), tx, u, "invitation_accepted", u.ID)
	})
}
