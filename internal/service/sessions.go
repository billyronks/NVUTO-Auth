package service

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/http"
	"time"
)

type committedRejection struct{ err error }

func (s *Service) issue(ctx context.Context, tx pgx.Tx, u identity, session string) (any, error) {
	access, refresh := randomToken(), randomToken()
	if session == "" {
		session = uuid.NewString()
		if _, e := tx.Exec(ctx, "INSERT INTO auth_sessions(id,user_id,version,access_hash,access_expires,expires,restricted) VALUES($1,$2,$3,$4,clock_timestamp()+interval '15 minutes',clock_timestamp()+interval '7 days',$5)", session, u.ID, u.Version, digest(access), u.MFARequired && u.Secret == ""); e != nil {
			return nil, e
		}
	} else {
		if _, e := tx.Exec(ctx, "UPDATE auth_sessions SET access_hash=$1,access_expires=LEAST(clock_timestamp()+interval '15 minutes',expires) WHERE id=$2", digest(access), session); e != nil {
			return nil, e
		}
	}
	if _, e := tx.Exec(ctx, "INSERT INTO auth_refresh(hash,session_id) VALUES($1,$2)", digest(refresh), session); e != nil {
		return nil, e
	}
	if e := audit(ctx, tx, u, "session_issued", u.ID); e != nil {
		return nil, e
	}
	var ttl int
	if e := tx.QueryRow(ctx, "SELECT GREATEST(0,ceil(extract(epoch FROM access_expires-clock_timestamp())))::int FROM auth_sessions WHERE id=$1", session).Scan(&ttl); e != nil {
		return nil, e
	}
	return map[string]any{"access_token": access, "refresh_token": refresh, "token_type": "Bearer", "expires_in": ttl, "session_id": session, "mfa_enrollment_required": u.MFARequired && u.Secret == "", "user": safeUser(u)}, nil
}
func (s *Service) refresh(w http.ResponseWriter, r *http.Request) (any, error) {
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	var id, session string
	if len(q.RefreshToken) != 43 {
		return nil, denied
	}
	e = s.DB.QueryRow(r.Context(), "SELECT ss.user_id,ss.id FROM auth_refresh rt JOIN auth_sessions ss ON ss.id=rt.session_id WHERE rt.hash=$1", digest(q.RefreshToken)).Scan(&id, &session)
	if e != nil {
		return nil, denied
	}
	return transact(r.Context(), s.DB, func(tx pgx.Tx) (any, error) {
		u, e := lockUser(r.Context(), tx, id)
		if e != nil {
			return nil, e
		}
		if !valid(u) || (u.MFARequired && u.Secret == "") {
			return nil, denied
		}
		var used, revoked bool
		var version int
		var expires time.Time
		e = tx.QueryRow(r.Context(), "SELECT rt.used,ss.revoked,ss.version,ss.expires FROM auth_refresh rt JOIN auth_sessions ss ON ss.id=rt.session_id WHERE rt.hash=$1 FOR UPDATE OF ss,rt", digest(q.RefreshToken)).Scan(&used, &revoked, &version, &expires)
		if e != nil {
			return nil, denied
		}
		if revoked || version != u.Version || time.Now().After(expires) {
			return nil, denied
		}
		if used {
			if _, e = tx.Exec(r.Context(), "UPDATE auth_sessions SET revoked=true WHERE id=$1", session); e != nil {
				return nil, e
			}
			if e = audit(r.Context(), tx, u, "refresh_reuse", u.ID); e != nil {
				return nil, e
			}
			return committedRejection{denied}, nil
		}
		if _, e = tx.Exec(r.Context(), "UPDATE auth_refresh SET used=true WHERE hash=$1", digest(q.RefreshToken)); e != nil {
			return nil, e
		}
		return s.issue(r.Context(), tx, u, session)
	})
}
func (s *Service) sensitive(r *http.Request, p principal, proof string, fn func(pgx.Tx, identity) (any, error)) (any, error) {
	return transact(r.Context(), s.DB, func(tx pgx.Tx) (any, error) {
		u, e := lockUser(r.Context(), tx, p.ID)
		if e != nil {
			return nil, e
		}
		if !valid(u) || u.Version != p.Version {
			return nil, denied
		}
		var ok bool
		if e = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM auth_sessions WHERE id=$1 AND user_id=$2 AND NOT revoked AND version=$3 AND access_expires>clock_timestamp() AND expires>clock_timestamp() AND access_hash=$4)", p.Session, p.ID, p.Version, p.AccessHash).Scan(&ok); e != nil {
			return nil, e
		}
		if !ok {
			return nil, denied
		}
		if e = consume(r.Context(), tx, u, "stepup", proof, p.Session); e != nil {
			return nil, e
		}
		return fn(tx, u)
	})
}
func (s *Service) logout(w http.ResponseWriter, r *http.Request) (any, error) {
	p, e := s.authenticate(r)
	if e == nil {
		return s.endSessions(r, p, p.Session, false)
	}
	q, decodeErr := decode(r)
	if decodeErr != nil {
		return nil, denied
	}
	if len(q.RefreshToken) != 43 {
		return nil, denied
	}
	var user, session string
	if e = s.DB.QueryRow(r.Context(), "SELECT ss.user_id,ss.id FROM auth_refresh rt JOIN auth_sessions ss ON ss.id=rt.session_id WHERE rt.hash=$1", digest(q.RefreshToken)).Scan(&user, &session); e != nil {
		if e == pgx.ErrNoRows {
			return nil, denied
		}
		return nil, e
	}
	// Possession of a stored renewal credential can only revoke its own family.
	return s.endSessions(r, principal{identity: identity{ID: user}, Session: session}, session, false)
}
func (s *Service) revokeSession(w http.ResponseWriter, r *http.Request) (any, error) {
	p, e := s.authenticate(r)
	if e != nil {
		return nil, e
	}
	id := r.PathValue("id")
	if _, e = uuid.Parse(id); e != nil {
		return nil, bad("invalid_session_id")
	}
	return s.endSessions(r, p, id, false)
}
func (s *Service) revokeOthers(w http.ResponseWriter, r *http.Request) (any, error) {
	p, e := s.authenticate(r)
	if e != nil {
		return nil, e
	}
	return s.endSessions(r, p, p.Session, true)
}
func (s *Service) endSessions(r *http.Request, p principal, id string, others bool) (any, error) {
	return transact(r.Context(), s.DB, func(tx pgx.Tx) (any, error) {
		u, e := lockUser(r.Context(), tx, p.ID)
		if e != nil {
			return nil, e
		}
		query := "UPDATE auth_sessions SET revoked=true WHERE user_id=$1 AND id=$2"
		if others {
			query = "UPDATE auth_sessions SET revoked=true WHERE user_id=$1 AND id<>$2"
		}
		if _, e = tx.Exec(r.Context(), query, p.ID, id); e != nil {
			return nil, e
		}
		return map[string]bool{"revoked": true}, audit(r.Context(), tx, u, "sessions_revoked", u.ID)
	})
}
func (s *Service) sessions(w http.ResponseWriter, r *http.Request) (any, error) {
	p, e := s.authenticate(r)
	if e != nil {
		return nil, e
	}
	rows, e := s.DB.Query(r.Context(), "SELECT id,created_at,expires FROM auth_sessions WHERE user_id=$1 AND NOT revoked AND expires>clock_timestamp() ORDER BY created_at", p.ID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id string
		var created, expires time.Time
		if e = rows.Scan(&id, &created, &expires); e != nil {
			return nil, e
		}
		out = append(out, map[string]any{"id": id, "created_at": created, "expires_at": expires, "current": id == p.Session})
	}
	return out, rows.Err()
}
func (s *Service) adminMFAReset(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.adminChange(r, true)
}
func (s *Service) userState(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.adminChange(r, false)
}
func (s *Service) adminChange(r *http.Request, mfa bool) (any, error) {
	p, e := s.authenticate(r)
	if e != nil {
		return nil, e
	}
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	if _, e = uuid.Parse(q.UserID); e != nil {
		return nil, bad("invalid_user_id")
	}
	if q.UserID == p.ID {
		return nil, forbidden
	}
	// Lock actor and target in UUID order to avoid opposite-direction deadlocks.
	return transact(r.Context(), s.DB, func(tx pgx.Tx) (any, error) {
		first, second := p.ID, q.UserID
		if first > second {
			first, second = second, first
		}
		a, e := lockUser(r.Context(), tx, first)
		if e != nil {
			return nil, denied
		}
		b, e := lockUser(r.Context(), tx, second)
		if e != nil {
			return nil, denied
		}
		actor, target := a, b
		if actor.ID != p.ID {
			actor, target = b, a
		}
		if !valid(actor) || actor.Version != p.Version || actor.Role != "owner" || target.Tenant != actor.Tenant || target.Role == "owner" || !target.Verified {
			return nil, forbidden
		}
		if e = activeSession(r.Context(), tx, p); e != nil {
			return nil, e
		}
		var alive bool
		if e = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM auth_sessions WHERE id=$1 AND NOT revoked AND version=$2 AND access_expires>clock_timestamp() AND expires>clock_timestamp())", p.Session, p.Version).Scan(&alive); e != nil {
			return nil, e
		}
		if !alive {
			return nil, denied
		}
		if e = consume(r.Context(), tx, actor, "stepup", q.Proof, p.Session); e != nil {
			return nil, e
		}
		event := "user_disabled"
		if mfa {
			event = "admin_mfa_reset"
			if _, e = tx.Exec(r.Context(), "UPDATE auth_users SET mfa_secret=NULL,mfa_required=true,last_totp_step=-1 WHERE id=$1", target.ID); e != nil {
				return nil, e
			}
			if _, e = tx.Exec(r.Context(), "DELETE FROM auth_recovery WHERE user_id=$1", target.ID); e != nil {
				return nil, e
			}
		} else {
			if q.State != "disabled" && q.State != "active" {
				return nil, bad("invalid_user_state")
			}
			if _, e = tx.Exec(r.Context(), "UPDATE auth_users SET active=$1 WHERE id=$2", q.State == "active", target.ID); e != nil {
				return nil, e
			}
			if q.State == "active" {
				event = "user_enabled"
			}
		}
		if e = revoke(r.Context(), tx, target.ID); e != nil {
			return nil, e
		}
		if e = s.queue(r.Context(), tx, target, "security-notice", ""); e != nil {
			return nil, e
		}
		return map[string]bool{"changed": true}, audit(r.Context(), tx, actor, event, target.ID)
	})
}

func activeSession(ctx context.Context, tx pgx.Tx, p principal) error {
	var ok bool
	if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM auth_sessions WHERE id=$1 AND user_id=$2 AND NOT revoked AND version=$3 AND access_expires>clock_timestamp() AND expires>clock_timestamp() AND access_hash=$4)", p.Session, p.ID, p.Version, p.AccessHash).Scan(&ok); e != nil {
		return e
	}
	if !ok {
		return denied
	}
	return nil
}
