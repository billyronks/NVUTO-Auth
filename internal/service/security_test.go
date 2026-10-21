package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestEncryptionConfiguration(t *testing.T) {
	key := []byte(strings.Repeat("a", 32))
	c := Config{ActiveKey: "one", Keys: map[string][]byte{"one": key}}
	encrypted, e := c.encrypt("secret")
	if e != nil {
		t.Fatal(e)
	}
	plain, e := c.decrypt(encrypted)
	if e != nil || plain != "secret" {
		t.Fatal("roundtrip", e)
	}
	c.ActiveKey = "two"
	c.Keys["two"] = []byte(strings.Repeat("b", 32))
	if _, e = c.decrypt(encrypted); e != nil {
		t.Fatal("old record unreadable after rotation", e)
	}
	rotated, e := c.encrypt(plain)
	if e != nil || !strings.HasPrefix(rotated, "two:") {
		t.Fatal("rotation", e)
	}
	delete(c.Keys, "one")
	if _, e = c.decrypt(encrypted); e == nil {
		t.Fatal("unknown key accepted")
	}
	for _, raw := range []string{"", "one:AA", "unknown:AAAA", rotated[:len(rotated)-1] + "!"} {
		if _, e = c.decrypt(raw); e == nil {
			t.Fatal("malformed ciphertext accepted")
		}
	}
}
func TestConfigFailsClosed(t *testing.T) {
	for _, name := range []string{"AUTH_ENCRYPTION_KEYS", "AUTH_ACTIVE_KEY", "DATABASE_URL", "PUBLIC_URL", "SMTP_HOST", "MAIL_FROM", "REGISTRATION_MODE"} {
		t.Setenv(name, "")
	}
	t.Setenv("JWT_SECRET", strings.Repeat("f", 64))
	if _, e := LoadConfig(); e == nil {
		t.Fatal("fallback key accepted")
	}
	t.Setenv("AUTH_ENCRYPTION_KEYS", "v1:"+strings.Repeat("a", 64))
	t.Setenv("AUTH_ACTIVE_KEY", "v1")
	t.Setenv("DATABASE_URL", "postgres://localhost/unused")
	t.Setenv("PUBLIC_URL", "https://auth.example.test")
	t.Setenv("SMTP_HOST", "smtp.example.test")
	t.Setenv("MAIL_FROM", "auth@example.test")
	if _, e := LoadConfig(); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{"http://public.example.test", "https://user:pw@example.test", "https://example.test/path", "https://example.test?redirect=bad"} {
		t.Setenv("PUBLIC_URL", raw)
		if _, e := LoadConfig(); e == nil {
			t.Fatal("invalid origin accepted", raw)
		}
	}
}
func TestStrictRequestsAndBrowserHeaders(t *testing.T) {
	for _, body := range []string{"{", "{} {}", `{"temporary_password":"known"}`, `{"unknown":true}`} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		if _, e := decode(r); e == nil {
			t.Fatal("unsafe request accepted", body)
		}
	}
	s := &Service{Config: Config{PublicURL: "https://auth.example.test"}}
	r := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader("{}"))
	r.Header.Set("Origin", "https://attacker.example")
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	r = httptest.NewRequest("GET", "/account", nil)
	w = httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("browser headers missing")
	}
	var q request
	r = httptest.NewRequest("POST", "/", strings.NewReader(`{"token":"abc"}`))
	q, e := decode(r)
	if e != nil || q.Token != "abc" {
		t.Fatal(q, e)
	}
	_, _ = json.Marshal(q)
	if _, e = s.authenticate(httptest.NewRequest(http.MethodGet, "/", nil)); e == nil {
		t.Fatal("anonymous authorized")
	}
}
func TestPasswordPolicy(t *testing.T) {
	for _, p := range []string{"short", strings.Repeat("a", 73)} {
		if passwordPolicy(p) == nil {
			t.Fatal("bad password accepted")
		}
	}
	if passwordPolicy("a long unique passphrase") != nil {
		t.Fatal("passphrase rejected")
	}
}

func TestProxyTrustAndCookieRejection(t *testing.T) {
	s := &Service{}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.1:443"
	r.Header.Set("X-Forwarded-For", "198.51.100.99")
	ip, e := s.clientIP(r)
	if e != nil || ip != "192.0.2.1" {
		t.Fatal(ip, e)
	}
	s.Config.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	r.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.99")
	ip, e = s.clientIP(r)
	if e != nil || ip != "198.51.100.99" {
		t.Fatal(ip, e)
	}
	r.Header.Set("X-Forwarded-For", "broken")
	if _, e = s.clientIP(r); e == nil {
		t.Fatal("malformed proxy accepted")
	}
	r.AddCookie(&http.Cookie{Name: "nvuto_access_token", Value: randomToken()})
	r.Header.Set("X-User-ID", "forged")
	r.Header.Set("X-Tenant-ID", "forged")
	if _, e = s.authenticate(r); e == nil {
		t.Fatal("cookie or forged identity accepted")
	}
}
