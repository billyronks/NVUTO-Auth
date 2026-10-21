package service

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

//go:embed schema.sql
var Schema string

type Service struct {
	DB     *pgxpool.Pool
	Config Config
}
type identity struct {
	MFARequired                                     bool
	ID, Tenant, Email, Name, Role, Password, Secret string
	Version                                         int
	Active, Verified, TenantActive                  bool
}
type principal struct {
	identity
	Session    string
	AccessHash string
	Restricted bool
}
type request struct {
	Tenant          string `json:"tenant"`
	Email           string `json:"email"`
	Name            string `json:"name"`
	Password        string `json:"password"`
	NewPassword     string `json:"new_password"`
	CurrentPassword string `json:"current_password"`
	Code            string `json:"code"`
	RecoveryCode    string `json:"recovery_code"`
	Token           string `json:"token"`
	RefreshToken    string `json:"refresh_token"`
	Proof           string `json:"proof"`
	UserID          string `json:"user_id"`
	State           string `json:"state"`
	Role            string `json:"role"`
}
type apiError struct {
	status int
	code   string
}

func (e apiError) Error() string { return e.code }

var denied = apiError{401, "invalid_credentials"}
var forbidden = apiError{403, "forbidden"}

func bad(code string) error { return apiError{400, code} }

type endpoint func(http.ResponseWriter, *http.Request) (any, error)

func output(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

var requestFields = map[string]string{
	"POST /api/v1/auth/register":                "tenant email password name",
	"POST /api/v1/auth/verify-email":            "token",
	"POST /api/v1/auth/resend-verification":     "tenant email",
	"POST /api/v1/auth/login":                   "tenant email password",
	"POST /api/v1/auth/mfa/verify":              "token code recovery_code",
	"POST /api/v1/auth/refresh":                 "refresh_token",
	"POST /api/v1/auth/logout":                  "refresh_token",
	"POST /api/v1/auth/forgot-password":         "tenant email",
	"POST /api/v1/auth/reset-password":          "token new_password",
	"POST /api/v1/auth/change-password":         "proof new_password",
	"POST /api/v1/auth/step-up":                 "password code recovery_code",
	"POST /api/v1/auth/mfa/setup":               "proof",
	"POST /api/v1/auth/mfa/confirm":             "token code",
	"POST /api/v1/auth/mfa/disable":             "proof",
	"POST /api/v1/auth/invitations":             "email name proof",
	"POST /api/v1/auth/invitations/{id}/resend": "proof",
	"DELETE /api/v1/auth/invitations/{id}":      "proof",
	"POST /api/v1/auth/invitations/accept":      "token new_password",
	"POST /api/v1/auth/admin/mfa-reset":         "user_id proof",
	"POST /api/v1/auth/admin/user-state":        "user_id state proof",
}

func decode(r *http.Request) (request, error) {
	var q request
	var raw json.RawMessage
	decoder := json.NewDecoder(r.Body)
	if decoder.Decode(&raw) != nil {
		return q, bad("invalid_request")
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return q, bad("invalid_request")
	}
	var fields map[string]json.RawMessage
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &fields) != nil {
		return q, bad("invalid_request")
	}
	allowed := requestFields[r.Pattern]
	if allowed == "" {
		allowed = "tenant email name password new_password code recovery_code token refresh_token proof user_id state"
	}
	for key := range fields {
		if !strings.Contains(" "+allowed+" ", " "+key+" ") {
			return q, bad("invalid_request")
		}
	}
	if json.Unmarshal(raw, &q) != nil {
		return q, bad("invalid_request")
	}
	return q, nil
}

func (s *Service) wrap(fn endpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		// No cookies, forwarded identity, or proxy IP headers authorize this API.
		if origin := r.Header.Get("Origin"); origin != "" && origin != strings.TrimRight(s.Config.PublicURL, "/") {
			output(w, 403, map[string]string{"error": "origin_denied"})
			return
		}
		ip, e := s.clientIP(r)
		if e != nil {
			s.writeError(w, bad("invalid_proxy_address"))
			return
		}
		max := 60
		if r.Method == "GET" {
			max = 1200
		}
		if e = s.limit(ctx, digest(ip)+":"+r.Pattern, max); e != nil {
			s.writeError(w, e)
			return
		}
		v, e := fn(w, r)
		if e != nil {
			s.writeError(w, e)
			return
		}
		output(w, 200, map[string]any{"data": v})
	}
}
func (s *Service) writeError(w http.ResponseWriter, e error) {
	var a apiError
	if errors.As(e, &a) {
		output(w, a.status, map[string]string{"error": a.code})
		return
	}
	// Database and delivery errors may contain PII or infrastructure secrets.
	log.Print("auth operation failed")
	output(w, 503, map[string]string{"error": "service_unavailable"})
}
func (s *Service) limit(ctx context.Context, key string, max int) error {
	var count int
	e := s.DB.QueryRow(ctx, `INSERT INTO auth_rate(bucket,window_start,count) VALUES($1,clock_timestamp(),1)
	ON CONFLICT(bucket) DO UPDATE SET count=CASE WHEN auth_rate.window_start<clock_timestamp()-interval '15 minutes' THEN 1 ELSE auth_rate.count+1 END,
	window_start=CASE WHEN auth_rate.window_start<clock_timestamp()-interval '15 minutes' THEN clock_timestamp() ELSE auth_rate.window_start END RETURNING count`, key).Scan(&count)
	if e != nil {
		return e
	}
	if count > max {
		return apiError{429, "rate_limited"}
	}
	return nil
}
func userRow(row pgx.Row) (identity, error) {
	var u identity
	e := row.Scan(&u.ID, &u.Tenant, &u.Email, &u.Name, &u.Role, &u.Password, &u.Secret, &u.Version, &u.Active, &u.Verified, &u.TenantActive, &u.MFARequired)
	return u, e
}

const userColumns = `u.id,u.tenant_id,u.email,u.name,u.role,u.password_hash,COALESCE(u.mfa_secret,''),u.version,u.active,u.verified,t.active,u.mfa_required`

func lockUser(ctx context.Context, tx pgx.Tx, id string) (identity, error) {
	return userRow(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM auth_users u JOIN auth_tenants t ON t.id=u.tenant_id WHERE u.id=$1 FOR UPDATE OF u FOR SHARE OF t`, id))
}
func valid(u identity) bool { return u.Active && u.Verified && u.TenantActive }
func (s *Service) authenticate(r *http.Request) (principal, error) {
	var p principal
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return p, denied
	}
	raw := strings.TrimPrefix(header, "Bearer ")
	if len(raw) != 43 {
		return p, denied
	}
	e := s.DB.QueryRow(r.Context(), `SELECT `+userColumns+`,ss.id,ss.restricted FROM auth_sessions ss JOIN auth_users u ON u.id=ss.user_id JOIN auth_tenants t ON t.id=u.tenant_id
	WHERE ss.access_hash=$1 AND NOT ss.revoked AND ss.access_expires>clock_timestamp() AND ss.expires>clock_timestamp() AND ss.version=u.version`, digest(raw)).Scan(&p.ID, &p.Tenant, &p.Email, &p.Name, &p.Role, &p.Password, &p.Secret, &p.Version, &p.Active, &p.Verified, &p.TenantActive, &p.MFARequired, &p.Session, &p.Restricted)
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return p, denied
		}
		return p, e
	}
	if !valid(p.identity) {
		return p, denied
	}
	p.AccessHash = digest(raw)
	if p.Restricted && r.URL.Path != "/api/v1/auth/mfa/setup" && r.URL.Path != "/api/v1/auth/mfa/confirm" && r.URL.Path != "/api/v1/auth/step-up" && r.URL.Path != "/api/v1/auth/logout" {
		return p, forbidden
	}
	return p, nil
}
func transact(ctx context.Context, db *pgxpool.Pool, fn func(pgx.Tx) (any, error)) (any, error) {
	tx, e := db.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	v, e := fn(tx)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	if rejection, ok := v.(committedRejection); ok {
		return nil, rejection.err
	}
	return v, nil
}
func audit(ctx context.Context, tx pgx.Tx, u identity, event, target string) error {
	_, e := tx.Exec(ctx, `INSERT INTO auth_audit(tenant_id,actor_id,event,target_id) VALUES($1,$2,$3,$4)`, u.Tenant, u.ID, event, target)
	return e
}
func revoke(ctx context.Context, tx pgx.Tx, id string) error {
	if _, e := tx.Exec(ctx, `UPDATE auth_users SET version=version+1,pending_secret=NULL,pending_expires=NULL,pending_version=NULL,pending_token=NULL,pending_attempts=0 WHERE id=$1`, id); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, `UPDATE auth_sessions SET revoked=true WHERE user_id=$1`, id); e != nil {
		return e
	}
	_, e := tx.Exec(ctx, `DELETE FROM auth_grants WHERE user_id=$1`, id)
	return e
}
func grant(ctx context.Context, tx pgx.Tx, u identity, kind string, ttl time.Duration) (string, error) {
	raw := randomToken()
	_, e := tx.Exec(ctx, `INSERT INTO auth_grants(hash,user_id,kind,version,expires) VALUES($1,$2,$3,$4,clock_timestamp()+$5*interval '1 second')`, digest(raw), u.ID, kind, u.Version, int64(ttl/time.Second))
	return raw, e
}
func consume(ctx context.Context, tx pgx.Tx, u identity, kind, raw string, session ...string) error {
	bound := ""
	if len(session) > 0 {
		bound = session[0]
	}
	tag, e := tx.Exec(ctx, `DELETE FROM auth_grants WHERE hash=$1 AND user_id=$2 AND kind=$3 AND version=$4 AND expires>clock_timestamp() AND attempts<5 AND ($5='' OR session_id::text=$5)`, digest(raw), u.ID, kind, u.Version, bound)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return denied
	}
	return nil
}
func (s *Service) queue(ctx context.Context, tx pgx.Tx, u identity, kind, token string) error {
	// The fragment is never transmitted in HTTP logs or Referer headers.
	body := "NVUTO Auth\r\n\r\nComplete " + kind + " for workspace " + u.Tenant + ":\r\n" + strings.TrimRight(s.Config.PublicURL, "/") + "/account#action=" + kind + "&token=" + token + "\r\n\r\nIf you did not request this, ignore this message."
	if kind == "security-notice" {
		body = "NVUTO Auth account security settings changed. If this was unexpected, contact your workspace operator."
	}
	encrypted, e := s.Config.encrypt(body)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO auth_outbox(recipient,encrypted_body) VALUES($1,$2)`, u.Email, encrypted)
	return e
}
func normalizedEmail(e string) (string, error) {
	e = strings.ToLower(strings.TrimSpace(e))
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || len(e) > 254 {
		return "", bad("invalid_email")
	}
	return e, nil
}
func hashPassword(p string) (string, error) {
	if e := passwordPolicy(p); e != nil {
		return "", bad("password_policy")
	}
	b, e := bcrypt.GenerateFromPassword([]byte(p), 12)
	return string(b), e
}
func safeUser(u identity) any {
	return map[string]any{"id": u.ID, "tenant_id": u.Tenant, "email": u.Email, "name": u.Name, "role": u.Role, "mfa_enabled": u.Secret != ""}
}

func (s *Service) Routes() http.Handler {
	m := http.NewServeMux()
	for route, fn := range map[string]endpoint{
		"POST /api/v1/auth/register": s.register, "POST /api/v1/auth/verify-email": s.verifyEmail,
		"POST /api/v1/auth/resend-verification": s.resendVerification, "POST /api/v1/auth/login": s.login,
		"POST /api/v1/auth/mfa/verify": s.verifyMFA, "POST /api/v1/auth/refresh": s.refresh,
		"GET /api/v1/auth/me": s.me, "POST /api/v1/auth/logout": s.logout,
		"POST /api/v1/auth/forgot-password": s.forgot, "POST /api/v1/auth/reset-password": s.reset,
		"POST /api/v1/auth/change-password": s.changePassword, "POST /api/v1/auth/step-up": s.stepup,
		"POST /api/v1/auth/mfa/setup": s.setupMFA, "POST /api/v1/auth/mfa/confirm": s.confirmMFA,
		"POST /api/v1/auth/mfa/disable": s.disableMFA, "GET /api/v1/auth/sessions": s.sessions,
		"DELETE /api/v1/auth/sessions/{id}": s.revokeSession, "POST /api/v1/auth/sessions/revoke-others": s.revokeOthers,
		"POST /api/v1/auth/invitations":             s.invite,
		"POST /api/v1/auth/invitations/{id}/resend": s.manageInvite,
		"DELETE /api/v1/auth/invitations/{id}":      s.manageInvite, "POST /api/v1/auth/invitations/accept": s.acceptInvite,
		"POST /api/v1/auth/admin/mfa-reset": s.adminMFAReset, "POST /api/v1/auth/admin/user-state": s.userState,
	} {
		m.HandleFunc(route, s.wrap(fn))
	}
	m.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { output(w, 200, map[string]string{"status": "alive"}) })
	m.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, c := context.WithTimeout(r.Context(), 2*time.Second)
		defer c()
		var v int
		e := s.DB.QueryRow(ctx, `SELECT version FROM auth_schema WHERE version=1 AND NOT EXISTS(SELECT 1 FROM auth_outbox WHERE delivered_at IS NULL AND (attempts>=3 OR next_attempt<clock_timestamp()-interval '15 minutes'))`).Scan(&v)
		if e != nil {
			output(w, 503, map[string]string{"status": "unavailable"})
			return
		}
		output(w, 200, map[string]string{"status": "ready"})
	})
	m.HandleFunc("GET /account", accountPage)
	m.HandleFunc("GET /account.js", accountScript)
	return m
}

func (s *Service) Bootstrap(ctx context.Context, slug, email, name, password string) error {
	if utf8.RuneCountInString(name) > 120 {
		return bad("name_too_long")
	}
	email, e := normalizedEmail(email)
	if e != nil {
		return e
	}
	hash, e := hashPassword(password)
	if e != nil {
		return e
	}
	_, e = transact(ctx, s.DB, func(tx pgx.Tx) (any, error) {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(728104291)`); e != nil {
			return nil, e
		}
		var count int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM auth_users`).Scan(&count); e != nil {
			return nil, e
		}
		if count != 0 {
			return nil, errors.New("bootstrap is one-time; users already exist")
		}
		u := identity{ID: uuid.NewString(), Tenant: uuid.NewString(), Email: email, Name: name, Role: "owner"}
		if _, e := tx.Exec(ctx, `INSERT INTO auth_tenants(id,slug) VALUES($1,$2)`, u.Tenant, slug); e != nil {
			return nil, e
		}
		if _, e := tx.Exec(ctx, `INSERT INTO auth_users(id,tenant_id,email,name,password_hash,role) VALUES($1,$2,$3,$4,$5,'owner')`, u.ID, u.Tenant, email, name, hash); e != nil {
			return nil, e
		}
		token, e := grant(ctx, tx, u, "verify", 24*time.Hour)
		if e != nil {
			return nil, e
		}
		if e = s.queue(ctx, tx, u, "verify", token); e != nil {
			return nil, e
		}
		return nil, audit(ctx, tx, u, "bootstrap", u.ID)
	})
	return e
}
