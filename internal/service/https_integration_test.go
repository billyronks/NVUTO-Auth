//go:build integration

package service

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

// Exercise real sockets and certificate validation, rather than calling a recorder.
func testHTTPSLifecycle(t *testing.T, h harness) {
	backend := httptest.NewServer(h.s.Routes())
	defer backend.Close()
	upstream, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	edge := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		proxy.ServeHTTP(w, r)
	}))
	edge.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	edge.StartTLS()
	defer edge.Close()
	original := h.s.Config
	defer func() { h.s.Config = original }()
	h.s.Config.PublicURL = edge.URL
	h.s.Config.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	client := edge.Client()
	call := func(want int, method, path string, body any, access, origin string) map[string]any {
		t.Helper()
		b, _ := json.Marshal(body)
		req, e := http.NewRequest(method, edge.URL+"/api/v1/auth/"+path, bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		// The edge appends the real peer, so a caller cannot choose its rate-limit identity.
		req.Header.Set("X-Forwarded-For", "203.0.113.99")
		if access != "" {
			req.Header.Set("Authorization", "Bearer "+access)
		}
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s: got %d want %d: %s", path, resp.StatusCode, want, data)
		}
		if resp.Header.Get("Strict-Transport-Security") == "" || resp.Header.Get("Cache-Control") != "no-store" || len(resp.Cookies()) != 0 {
			t.Fatal("HTTPS security headers/cookie policy failed")
		}
		var out map[string]any
		if e = json.Unmarshal(data, &out); e != nil {
			t.Fatal(e)
		}
		if v, ok := out["data"].(map[string]any); ok {
			return v
		}
		return out
	}
	u, slug := h.user("member")
	q := map[string]string{"tenant": slug, "email": u.Email, "password": h.password}
	call(403, "POST", "login", q, "", "https://attacker.example.test")
	v := call(200, "POST", "login", q, "", edge.URL)
	access, refresh := token(v, "access_token"), token(v, "refresh_token")
	call(200, "GET", "me", nil, access, edge.URL)
	call(200, "POST", "forgot-password", map[string]string{"tenant": slug, "email": u.Email}, "", edge.URL)
	reset := h.latestToken(u.Email)
	replacement := randomToken()
	call(200, "POST", "reset-password", map[string]string{"token": reset, "new_password": replacement}, "", edge.URL)
	call(401, "POST", "reset-password", map[string]string{"token": reset, "new_password": replacement}, "", edge.URL)
	call(401, "GET", "me", nil, access, edge.URL)
	call(401, "POST", "refresh", map[string]string{"refresh_token": refresh}, "", edge.URL)
	q["password"] = replacement
	v = call(200, "POST", "login", q, "", edge.URL)
	access = token(v, "access_token")
	v = call(200, "POST", "refresh", map[string]string{"refresh_token": token(v, "refresh_token")}, "", edge.URL)
	call(401, "GET", "me", nil, access, edge.URL)
	access = token(v, "access_token")
	call(200, "POST", "logout", nil, access, edge.URL)
	call(401, "GET", "me", nil, access, edge.URL)
	// An untrusted edge certificate must not be accepted by an ordinary client.
	if resp, e := http.Get(edge.URL + "/ready"); e == nil {
		resp.Body.Close()
		t.Fatal("untrusted HTTPS certificate accepted")
	}
	endpoint := strings.TrimPrefix(edge.URL, "https://")
	if conn, e := tls.Dial("tcp", endpoint, &tls.Config{MaxVersion: tls.VersionTLS11, MinVersion: tls.VersionTLS10, RootCAs: client.Transport.(*http.Transport).TLSClientConfig.RootCAs}); e == nil {
		conn.Close()
		t.Fatal("legacy TLS accepted")
	}
}
