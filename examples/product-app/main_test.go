package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const tenant = "11111111-1111-4111-8111-111111111111"
const user = "22222222-2222-4222-8222-222222222222"

func TestProductTrustBoundaries(t *testing.T) {
	var mode atomic.Value
	mode.Store("valid")
	var calls atomic.Int32
	auth := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Cookie") != "" || r.Header.Get("X-User-ID") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Origin") != "" {
			t.Error("caller metadata forwarded")
		}
		if r.URL.Path == "/api/v1/auth/login" {
			io.WriteString(w, "{\"data\":{\"mfa_required\":true,\"challenge\":\"synthetic\"}}")
			return
		}
		if r.Header.Get("Authorization") != "Bearer synthetic" {
			w.WriteHeader(401)
			return
		}
		switch mode.Load().(string) {
		case "revoked":
			w.WriteHeader(401)
		case "down":
			w.WriteHeader(503)
		case "malformed":
			io.WriteString(w, "{\"data\":{}}")
		case "redirect":
			http.Redirect(w, r, "https://attacker.invalid", 302)
		default:
			id := tenant
			if mode.Load().(string) == "other-workspace" {
				id = user
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"id": user, "tenant_id": id}})
		}
	}))
	defer auth.Close()
	app, e := newApp(config{auth.URL, "http://localhost:8090", tenant}, auth.Client())
	if e != nil {
		t.Fatal(e)
	}
	call := func(want int, method, path, bearer, origin string) {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader("{}"))
		r.Header.Set("Authorization", bearer)
		r.Header.Set("Origin", origin)
		r.Header.Set("Cookie", "forged=identity")
		r.Header.Set("X-User-ID", user)
		r.Header.Set("X-Forwarded-For", "203.0.113.1")
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s: got %d want %d: %s", path, w.Code, want, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("response policy")
		}
	}
	call(401, "GET", "/api/projects", "", "")
	if calls.Load() != 0 {
		t.Fatal("missing credentials reached upstream")
	}
	call(403, "POST", "/api/auth/login", "", "https://attacker.invalid")
	if calls.Load() != 0 {
		t.Fatal("cross-origin login reached upstream")
	}
	call(200, "POST", "/api/auth/login", "", "http://localhost:8090")
	for _, test := range []struct {
		mode string
		want int
	}{{"valid", 200}, {"other-workspace", 403}, {"revoked", 401}, {"down", 503}, {"malformed", 503}, {"redirect", 503}} {
		mode.Store(test.mode)
		call(test.want, "GET", "/api/projects", "Bearer synthetic", "")
	}
	call(404, "POST", "/api/auth/admin/user-state", "Bearer synthetic", "")
	r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(strings.Repeat("x", 16385)))
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatal("body limit not enforced", w.Code)
	}
}
func TestConfiguration(t *testing.T) {
	for _, c := range []config{{"http://remote.example", "http://localhost:8090", tenant}, {"https://auth.example/path", "http://localhost:8090", tenant}, {"https://auth.example", "http://localhost:8090", ""}} {
		if _, e := newApp(c, http.DefaultClient); e == nil {
			t.Fatal("unsafe configuration accepted", c)
		}
	}
}
