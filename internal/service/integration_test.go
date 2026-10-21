//go:build integration

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type harness struct {
	t        *testing.T
	s        *Service
	admin    *pgxpool.Pool
	handler  http.Handler
	password string
}

var requestNumber atomic.Uint32

func (h harness) call(method, path string, body any, access string) (int, map[string]any) {
	h.t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(method, "/api/v1/auth/"+path, bytes.NewReader(b))
	r.RemoteAddr = fmt.Sprintf("192.0.2.%d:10000", requestNumber.Add(1))
	if access != "" {
		r.Header.Set("Authorization", "Bearer "+access)
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if v, ok := out["data"].(map[string]any); ok {
		return w.Code, v
	}
	return w.Code, out
}
func (h harness) expect(want int, method, path string, body any, access string) map[string]any {
	h.t.Helper()
	code, v := h.call(method, path, body, access)
	if code != want {
		h.t.Fatalf("%s %s: status %d want %d; %v", method, path, code, want, v)
	}
	return v
}
func (h harness) sql(query string, args ...any) {
	h.t.Helper()
	if _, e := h.admin.Exec(context.Background(), query, args...); e != nil {
		h.t.Fatal(e)
	}
}
func (h harness) user(role string) (identity, string) {
	h.t.Helper()
	u := identity{ID: uuid.NewString(), Tenant: uuid.NewString(), Email: "person@example.test", Name: "Synthetic User", Role: role, Active: true, Verified: true, TenantActive: true}
	slug := "test-" + uuid.NewString()
	hash, e := hashPassword(h.password)
	if e != nil {
		h.t.Fatal(e)
	}
	h.sql("INSERT INTO auth_tenants(id,slug) VALUES($1,$2)", u.Tenant, slug)
	h.sql("INSERT INTO auth_users(id,tenant_id,email,name,password_hash,role,verified) VALUES($1,$2,$3,$4,$5,$6,true)", u.ID, u.Tenant, u.Email, u.Name, hash, role)
	return u, slug
}
func (h harness) login(u identity, slug string) map[string]any {
	return h.expect(200, "POST", "login", map[string]any{"tenant": slug, "email": u.Email, "password": h.password}, "")
}
func token(v map[string]any, k string) string { s, _ := v[k].(string); return s }
func (h harness) grant(u identity, kind string) string {
	h.t.Helper()
	var raw string
	_, e := transact(context.Background(), h.s.DB, func(tx pgx.Tx) (any, error) {
		current, e := lockUser(context.Background(), tx, u.ID)
		if e != nil {
			return nil, e
		}
		raw, e = grant(context.Background(), tx, current, kind, 5*time.Minute)
		return nil, e
	})
	if e != nil {
		h.t.Fatal(e)
	}
	return raw
}
func (h harness) proof(access string) string {
	return token(h.expect(200, "POST", "step-up", map[string]any{"password": h.password}, access), "proof")
}
func (h harness) latestToken(email string) string {
	h.t.Helper()
	var encrypted string
	if e := h.admin.QueryRow(context.Background(), "SELECT encrypted_body FROM auth_outbox WHERE recipient=$1 ORDER BY id DESC LIMIT 1", email).Scan(&encrypted); e != nil {
		h.t.Fatal(e)
	}
	body, e := h.s.Config.decrypt(encrypted)
	if e != nil {
		h.t.Fatal(e)
	}
	_, tail, ok := strings.Cut(body, "&token=")
	if !ok {
		h.t.Fatal("token not queued")
	}
	return strings.Fields(tail)[0]
}
func TestPublicLifecycle(t *testing.T) {
	if os.Getenv("AUTH_ISOLATED_TEST") != "1" {
		t.Fatal("integration tests require scripts/integration.py and its fresh private database")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, os.Getenv("AUTH_TEST_ADMIN_URL"))
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	if _, e = admin.Exec(ctx, Schema); e != nil {
		t.Fatal(e)
	}
	if _, e = admin.Exec(ctx, "GRANT USAGE ON SCHEMA public TO auth_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO auth_runtime; GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO auth_runtime"); e != nil {
		t.Fatal(e)
	}
	db, e := pgxpool.New(ctx, os.Getenv("AUTH_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	c := Config{PublicURL: "https://auth.example.test", ActiveKey: "v1", Keys: map[string][]byte{"v1": []byte(strings.Repeat("x", 32))}, Registration: true}
	s := &Service{DB: db, Config: c}
	h := harness{t: t, s: s, admin: admin, handler: s.Routes(), password: randomToken()}
	t.Run("bootstrap-verification-single-use", func(t *testing.T) {
		h.t = t
		if e = s.Bootstrap(ctx, "workspace", "owner@example.test", "Owner", h.password); e != nil {
			t.Fatal(e)
		}
		if e = s.Bootstrap(ctx, "other", "other@example.test", "Other", h.password); e == nil {
			t.Fatal("second bootstrap allowed")
		}
		q := map[string]any{"tenant": "workspace", "email": "owner@example.test", "password": h.password}
		h.expect(401, "POST", "login", q, "")
		raw := h.latestToken("owner@example.test")
		h.expect(200, "POST", "verify-email", map[string]string{"token": raw}, "")
		h.expect(401, "POST", "verify-email", map[string]string{"token": raw}, "")
		h.expect(200, "POST", "login", q, "")
	})
	t.Run("registration-email-and-privilege-boundary", func(t *testing.T) {
		h.t = t
		u, slug := h.user("member")
		email := "registered@example.test"
		q := map[string]any{"tenant": slug, "email": email, "password": h.password, "role": "owner"}
		h.expect(400, "POST", "register", q, "")
		delete(q, "role")
		h.expect(200, "POST", "register", q, "")
		h.expect(401, "POST", "login", q, "")
		raw := h.latestToken(email)
		h.expect(200, "POST", "verify-email", map[string]string{"token": raw}, "")
		v := h.expect(200, "POST", "login", q, "")
		access := token(v, "access_token")
		me := h.expect(200, "GET", "me", nil, access)
		if me["role"] != "member" || me["tenant_id"] != u.Tenant {
			t.Fatal(me)
		}
		proof := h.proof(access)
		h.expect(403, "POST", "invitations", map[string]any{"proof": proof, "email": "no@example.test"}, access)
		h.expect(404, "POST", "roles", map[string]string{}, access)
		h.expect(400, "POST", "reset-password", map[string]string{"email": email, "temporary_password": h.password, "new_password": randomToken()}, "")
	})
	t.Run("HTTPS-reverse-proxy-lifecycle", func(t *testing.T) { h.t = t; testHTTPSLifecycle(t, h) })
	t.Run("revocation-and-refresh-reuse", func(t *testing.T) {
		h.t = t
		u, slug := h.user("member")
		v := h.login(u, slug)
		access, refresh := token(v, "access_token"), token(v, "refresh_token")
		v = h.expect(200, "POST", "refresh", map[string]string{"refresh_token": refresh}, "")
		newAccess, newRefresh := token(v, "access_token"), token(v, "refresh_token")
		h.expect(401, "GET", "me", nil, access)
		h.expect(401, "POST", "refresh", map[string]string{"refresh_token": refresh}, "")
		h.expect(401, "GET", "me", nil, newAccess)
		h.expect(401, "POST", "refresh", map[string]string{"refresh_token": newRefresh}, "")
		v = h.login(u, slug)
		access = token(v, "access_token")
		h.expect(200, "POST", "logout", nil, access)
		h.expect(401, "GET", "me", nil, access)
	})
	t.Run("password-reset-races-refresh-and-preserves-MFA", func(t *testing.T) {
		h.t = t
		u, slug := h.user("member")
		v := h.login(u, slug)
		access, refresh := token(v, "access_token"), token(v, "refresh_token")
		secret := "JBSWY3DPEHPK3PXP"
		enc, _ := c.encrypt(secret)
		h.sql("UPDATE auth_users SET mfa_secret=$1 WHERE id=$2", enc, u.ID)
		raw := h.grant(u, "reset")
		staleMFA := h.grant(u, "mfa")
		replacement := randomToken()
		var wg sync.WaitGroup
		wg.Add(2)
		var resetCode, refreshCode int
		var rotated map[string]any
		go func() {
			defer wg.Done()
			resetCode, _ = h.call("POST", "reset-password", map[string]string{"token": raw, "new_password": replacement}, "")
		}()
		go func() {
			defer wg.Done()
			refreshCode, rotated = h.call("POST", "refresh", map[string]string{"refresh_token": refresh}, "")
		}()
		wg.Wait()
		if resetCode != 200 || (refreshCode != 200 && refreshCode != 401) {
			t.Fatalf("race reset=%d refresh=%d", resetCode, refreshCode)
		}
		h.expect(401, "GET", "me", nil, access)
		if refreshCode == 200 {
			h.expect(401, "GET", "me", nil, token(rotated, "access_token"))
			h.expect(401, "POST", "refresh", map[string]string{"refresh_token": token(rotated, "refresh_token")}, "")
		}
		h.expect(401, "POST", "reset-password", map[string]string{"token": raw, "new_password": replacement}, "")
		h.expect(401, "POST", "mfa/verify", map[string]string{"token": staleMFA, "code": "000000"}, "")
		v = h.expect(200, "POST", "login", map[string]string{"tenant": slug, "email": u.Email, "password": replacement}, "")
		if v["mfa_required"] != true || v["access_token"] != nil {
			t.Fatal("recovery bypassed MFA", v)
		}
	})
	t.Run("MFA-pending-expiry-replacement-and-replay", func(t *testing.T) {
		h.t = t
		u, slug := h.user("member")
		v := h.login(u, slug)
		access := token(v, "access_token")
		h.expect(401, "POST", "mfa/setup", map[string]string{}, access)
		setup := h.expect(200, "POST", "mfa/setup", map[string]string{"proof": h.proof(access)}, access)
		var activeSecret *string
		if e := admin.QueryRow(ctx, "SELECT mfa_secret FROM auth_users WHERE id=$1", u.ID).Scan(&activeSecret); e != nil || activeSecret != nil {
			t.Fatal("pending replaced active factor", e)
		}
		h.sql("UPDATE auth_users SET pending_expires=now()-interval '1 minute' WHERE id=$1", u.ID)
		code, _ := totp.GenerateCode(token(setup, "secret"), time.Now())
		h.expect(401, "POST", "mfa/confirm", map[string]string{"token": token(setup, "enrollment_token"), "code": code}, access)
		setup = h.expect(200, "POST", "mfa/setup", map[string]string{"proof": h.proof(access)}, access)
		code, _ = totp.GenerateCode(token(setup, "secret"), time.Now())
		confirmed := h.expect(200, "POST", "mfa/confirm", map[string]string{"token": token(setup, "enrollment_token"), "code": code}, access)
		h.expect(401, "GET", "me", nil, access)
		codes := confirmed["recovery_codes"].([]any)
		v = h.login(u, slug)
		challenge := token(v, "challenge")
		h.expect(401, "POST", "mfa/verify", map[string]string{"token": challenge, "code": code}, "")
		v = h.expect(200, "POST", "mfa/verify", map[string]string{"token": challenge, "recovery_code": codes[0].(string)}, "")
		access = token(v, "access_token")
		h.expect(401, "POST", "mfa/verify", map[string]string{"token": challenge, "recovery_code": codes[1].(string)}, "")
		h.expect(401, "POST", "step-up", map[string]string{"password": h.password}, access)
		h.expect(401, "POST", "step-up", map[string]string{"password": h.password, "recovery_code": codes[0].(string)}, access)
		proof := token(h.expect(200, "POST", "step-up", map[string]string{"password": h.password, "recovery_code": codes[1].(string)}, access), "proof")
		h.expect(200, "POST", "mfa/disable", map[string]string{"proof": proof}, access)
		h.expect(401, "GET", "me", nil, access)
		var count int
		admin.QueryRow(ctx, "SELECT count(*) FROM auth_recovery WHERE user_id=$1", u.ID).Scan(&count)
		if count != 0 {
			t.Fatal("recovery codes retained")
		}
	})
	t.Run("invitations-tenant-isolation-and-admin-reset", func(t *testing.T) {
		h.t = t
		owner, slug := h.user("owner")
		v := h.login(owner, slug)
		access := token(v, "access_token")
		email := "invited@example.test"
		v = h.expect(200, "POST", "invitations", map[string]string{"email": email, "proof": h.proof(access)}, access)
		target := token(v, "user_id")
		raw := h.latestToken(email)
		h.expect(200, "POST", "invitations/accept", map[string]string{"token": raw, "new_password": h.password}, "")
		h.expect(401, "POST", "invitations/accept", map[string]string{"token": raw, "new_password": h.password}, "")
		targetSession := h.expect(200, "POST", "login", map[string]string{"tenant": slug, "email": email, "password": h.password}, "")
		h.expect(403, "POST", "admin/mfa-reset", map[string]string{"user_id": owner.ID, "proof": h.proof(access)}, access)
		other, _ := h.user("member")
		h.expect(403, "POST", "admin/mfa-reset", map[string]string{"user_id": other.ID, "proof": h.proof(access)}, access)
		h.expect(200, "POST", "admin/mfa-reset", map[string]string{"user_id": target, "proof": h.proof(access)}, access)
		h.expect(401, "GET", "me", nil, token(targetSession, "access_token"))
		h.expect(401, "POST", "refresh", map[string]string{"refresh_token": token(targetSession, "refresh_token")}, "")
		enrollment := h.expect(200, "POST", "login", map[string]string{"tenant": slug, "email": email, "password": h.password}, "")
		if enrollment["mfa_enrollment_required"] != true {
			t.Fatal("admin reset failed to require enrollment")
		}
		h.expect(403, "GET", "me", nil, token(enrollment, "access_token"))
		h.expect(401, "POST", "refresh", map[string]string{"refresh_token": token(enrollment, "refresh_token")}, "")
		h.expect(401, "POST", "login", map[string]string{"tenant": slug + "-wrong", "email": owner.Email, "password": h.password}, "")
		h.sql("UPDATE auth_tenants SET active=false WHERE id=$1", owner.Tenant)
		h.expect(401, "GET", "me", nil, access)
		h.expect(401, "POST", "login", map[string]string{"tenant": slug, "email": owner.Email, "password": h.password}, "")
	})
	t.Run("transaction-failure-never-releases-session", func(t *testing.T) {
		h.t = t
		u, slug := h.user("member")
		h.sql("REVOKE INSERT ON auth_audit FROM auth_runtime")
		defer h.sql("GRANT INSERT ON auth_audit TO auth_runtime")
		h.expect(503, "POST", "login", map[string]string{"tenant": slug, "email": u.Email, "password": h.password}, "")
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM auth_sessions WHERE user_id=$1", u.ID).Scan(&count); e != nil || count != 0 {
			t.Fatal("phantom session", count, e)
		}
	})
	t.Run("delivery-failure-is-retriable-and-encrypted", func(t *testing.T) {
		h.t = t
		s.Config.SMTPHost = "127.0.0.1"
		s.Config.SMTPPort = "1"
		s.Config.MailFrom = "auth@example.test"
		done, e := s.DeliverOne(ctx)
		if e != nil || !done {
			t.Fatal(done, e)
		}
		var attempts int
		var encrypted string
		if e = admin.QueryRow(ctx, "SELECT attempts,encrypted_body FROM auth_outbox ORDER BY id LIMIT 1").Scan(&attempts, &encrypted); e != nil || attempts != 1 || !strings.HasPrefix(encrypted, "v1:") {
			t.Fatal(attempts, e)
		}
	})
	t.Run("concurrent-refresh-one-winner-and-family-revoked", func(t *testing.T) {
		h.t = t
		u, slug := h.user("member")
		v := h.login(u, slug)
		raw := token(v, "refresh_token")
		var wg sync.WaitGroup
		results := make(chan int, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				code, _ := h.call("POST", "refresh", map[string]string{"refresh_token": raw}, "")
				results <- code
			}()
		}
		wg.Wait()
		close(results)
		wins := 0
		losses := 0
		for code := range results {
			if code == 200 {
				wins++
			} else if code == 401 {
				losses++
			} else {
				t.Fatal(code)
			}
		}
		if wins != 1 || losses != 1 {
			t.Fatal(wins, losses)
		}
		var alive int
		admin.QueryRow(ctx, "SELECT count(*) FROM auth_sessions WHERE user_id=$1 AND NOT revoked", u.ID).Scan(&alive)
		if alive != 0 {
			t.Fatal("reused family survived")
		}
	})
	t.Run("rate-limiter-fails-closed", func(t *testing.T) {
		h.t = t
		u, slug := h.user("member")
		h.sql("REVOKE INSERT,UPDATE ON auth_rate FROM auth_runtime")
		defer h.sql("GRANT INSERT,UPDATE ON auth_rate TO auth_runtime")
		h.expect(503, "POST", "login", map[string]string{"tenant": slug, "email": u.Email, "password": h.password}, "")
	})
	t.Run("old-challenges-and-code-attempt-budget", func(t *testing.T) {
		h.t = t
		u, slug := h.user("member")
		enc, _ := c.encrypt("JBSWY3DPEHPK3PXP")
		h.sql("UPDATE auth_users SET mfa_secret=$1 WHERE id=$2", enc, u.ID)
		v := h.login(u, slug)
		raw := token(v, "challenge")
		for i := 0; i < 6; i++ {
			h.expect(401, "POST", "mfa/verify", map[string]string{"token": raw, "code": "invalid"}, "")
		}
		var attempts int
		if e := admin.QueryRow(ctx, "SELECT attempts FROM auth_grants WHERE hash=$1", digest(raw)).Scan(&attempts); e != nil || attempts != 5 {
			t.Fatal(attempts, e)
		}
		raw = h.grant(u, "mfa")
		h.sql("UPDATE auth_users SET version=version+1 WHERE id=$1", u.ID)
		h.expect(401, "POST", "mfa/verify", map[string]string{"token": raw, "code": "000000"}, "")
	})

	t.Run("encryption-key-rotation", func(t *testing.T) {
		s.Config.Keys["v2"] = []byte(strings.Repeat("y", 32))
		s.Config.ActiveKey = "v2"
		if e = s.RotateEncryption(ctx); e != nil {
			t.Fatal(e)
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM auth_users WHERE mfa_secret IS NOT NULL AND mfa_secret NOT LIKE 'v2:%'").Scan(&count); e != nil || count != 0 {
			t.Fatal(count, e)
		}
	})

	t.Run("read-workload", func(t *testing.T) {
		h.t = t
		u, slug := h.user("member")
		v := h.login(u, slug)
		access := token(v, "access_token")
		var wg sync.WaitGroup
		slots := make(chan struct{}, 8)
		latencies := make(chan time.Duration, 120)
		codes := make(chan int, 120)
		start := time.Now()
		for i := 0; i < 120; i++ {
			slots <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				begin := time.Now()
				code, _ := h.call("GET", "me", nil, access)
				codes <- code
				latencies <- time.Since(begin)
			}()
		}
		wg.Wait()
		close(latencies)
		close(codes)
		for code := range codes {
			if code != 200 {
				t.Fatal(code)
			}
		}
		values := []time.Duration{}
		for latency := range latencies {
			values = append(values, latency)
		}
		sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
		p95 := values[113]
		t.Logf("120 identity reads, concurrency 8: total=%s p50=%s p95=%s", time.Since(start), values[59], p95)
		if p95 > 2*time.Second {
			t.Fatal("development p95 target exceeded")
		}
	})
	t.Run("invitation-resend-and-revoke", func(t *testing.T) {
		h.t = t
		u, slug := h.user("owner")
		v := h.login(u, slug)
		access := token(v, "access_token")
		email := "revoked@example.test"
		v = h.expect(200, "POST", "invitations", map[string]string{"email": email, "proof": h.proof(access)}, access)
		id := token(v, "user_id")
		old := h.latestToken(email)
		h.expect(200, "POST", "invitations/"+id+"/resend", map[string]string{"proof": h.proof(access)}, access)
		fresh := h.latestToken(email)
		h.expect(401, "POST", "invitations/accept", map[string]string{"token": old, "new_password": h.password}, "")
		h.expect(200, "DELETE", "invitations/"+id, map[string]string{"proof": h.proof(access)}, access)
		h.expect(401, "POST", "invitations/accept", map[string]string{"token": fresh, "new_password": h.password}, "")
	})

	t.Run("lookup-failures-never-claim-email-success", func(t *testing.T) {
		h.t = t
		u, slug := h.user("member")
		h.sql("REVOKE SELECT ON auth_users FROM auth_runtime")
		defer h.sql("GRANT SELECT ON auth_users TO auth_runtime")
		h.expect(503, "POST", "forgot-password", map[string]string{"tenant": slug, "email": u.Email}, "")
		h.expect(503, "POST", "login", map[string]string{"tenant": slug, "email": u.Email, "password": h.password}, "")
	})

	t.Run("logout-revokes-expired-access-with-refresh", func(t *testing.T) {
		h.t = t
		u, slug := h.user("member")
		v := h.login(u, slug)
		h.sql("UPDATE auth_sessions SET access_expires=now()-interval '1 second' WHERE user_id=$1", u.ID)
		h.expect(200, "POST", "logout", map[string]string{"refresh_token": token(v, "refresh_token")}, token(v, "access_token"))
		h.expect(401, "POST", "refresh", map[string]string{"refresh_token": token(v, "refresh_token")}, "")
	})

}
