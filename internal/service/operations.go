package service

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/http"
	"time"
)

func (s *Service) manageInvite(w http.ResponseWriter, r *http.Request) (any, error) {
	p, e := s.authenticate(r)
	if e != nil {
		return nil, e
	}
	q, e := decode(r)
	if e != nil {
		return nil, e
	}
	id := r.PathValue("id")
	if _, e = uuid.Parse(id); e != nil {
		return nil, bad("invalid_user_id")
	}
	return s.sensitive(r, p, q.Proof, func(tx pgx.Tx, actor identity) (any, error) {
		if actor.Role != "owner" {
			return nil, forbidden
		}
		var u identity
		u, e = userRow(tx.QueryRow(r.Context(), "SELECT "+userColumns+" FROM auth_users u JOIN auth_tenants t ON t.id=u.tenant_id WHERE u.id=$1 AND u.tenant_id=$2 AND NOT u.verified AND NOT u.active FOR UPDATE OF u", id, actor.Tenant))
		if e != nil {
			return nil, denied
		}
		if _, e = tx.Exec(r.Context(), "DELETE FROM auth_grants WHERE user_id=$1 AND kind='invite'", id); e != nil {
			return nil, e
		}
		event := "invitation_resent"
		if r.Method == "DELETE" {
			event = "invitation_revoked"
			if _, e = tx.Exec(r.Context(), "DELETE FROM auth_users WHERE id=$1", id); e != nil {
				return nil, e
			}
		} else {
			raw, e := grant(r.Context(), tx, u, "invite", 24*time.Hour)
			if e != nil {
				return nil, e
			}
			if e = s.queue(r.Context(), tx, u, "invite", raw); e != nil {
				return nil, e
			}
		}
		return map[string]bool{"changed": true}, audit(r.Context(), tx, actor, event, id)
	})
}

// RotateEncryption is an offline maintenance command. Keep old keys configured
// through the operation and backup verification before retiring them.
func (s *Service) RotateEncryption(ctx context.Context) error {
	_, e := transact(ctx, s.DB, func(tx pgx.Tx) (any, error) {
		rows, e := tx.Query(ctx, "SELECT id,COALESCE(mfa_secret,''),COALESCE(pending_secret,'') FROM auth_users ORDER BY id FOR UPDATE")
		if e != nil {
			return nil, e
		}
		type record struct{ id, a, b string }
		records := []record{}
		for rows.Next() {
			var r record
			if e = rows.Scan(&r.id, &r.a, &r.b); e != nil {
				rows.Close()
				return nil, e
			}
			records = append(records, r)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
		for _, r := range records {
			var a, b any
			for i, raw := range []string{r.a, r.b} {
				if raw == "" {
					continue
				}
				plain, e := s.Config.decrypt(raw)
				if e != nil {
					return nil, e
				}
				value, e := s.Config.encrypt(plain)
				if e != nil {
					return nil, e
				}
				if i == 0 {
					a = value
				} else {
					b = value
				}
			}
			if _, e = tx.Exec(ctx, "UPDATE auth_users SET mfa_secret=$1,pending_secret=$2 WHERE id=$3", a, b, r.id); e != nil {
				return nil, e
			}
		}
		out, e := tx.Query(ctx, "SELECT id,encrypted_body FROM auth_outbox WHERE delivered_at IS NULL ORDER BY id FOR UPDATE")
		if e != nil {
			return nil, e
		}
		type message struct {
			id   int64
			body string
		}
		messages := []message{}
		for out.Next() {
			var m message
			if e = out.Scan(&m.id, &m.body); e != nil {
				out.Close()
				return nil, e
			}
			messages = append(messages, m)
		}
		e = out.Err()
		out.Close()
		if e != nil {
			return nil, e
		}
		for _, m := range messages {
			plain, e := s.Config.decrypt(m.body)
			if e != nil {
				return nil, e
			}
			encrypted, e := s.Config.encrypt(plain)
			if e != nil {
				return nil, e
			}
			if _, e = tx.Exec(ctx, "UPDATE auth_outbox SET encrypted_body=$1 WHERE id=$2", encrypted, m.id); e != nil {
				return nil, e
			}
		}
		return nil, nil
	})
	return e
}

func (s *Service) Cleanup(ctx context.Context) error {
	_, e := transact(ctx, s.DB, func(tx pgx.Tx) (any, error) {
		for _, query := range []string{"UPDATE auth_users SET pending_secret=NULL,pending_token=NULL,pending_expires=NULL,pending_version=NULL,pending_attempts=0 WHERE pending_expires<clock_timestamp()", "DELETE FROM auth_rate WHERE window_start<clock_timestamp()-interval '1 day'", "DELETE FROM auth_grants WHERE expires<clock_timestamp()", "DELETE FROM auth_sessions WHERE expires<clock_timestamp()-interval '1 day'", "DELETE FROM auth_outbox WHERE delivered_at<clock_timestamp()-interval '1 day' OR (delivered_at IS NULL AND next_attempt<clock_timestamp()-interval '30 days')", "DELETE FROM auth_audit WHERE created_at<clock_timestamp()-interval '180 days'"} {
			if _, e := tx.Exec(ctx, query); e != nil {
				return nil, e
			}
		}
		return nil, nil
	})
	return e
}
