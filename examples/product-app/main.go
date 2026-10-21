// A small existing product with its own protected API and a same-origin auth adapter.
package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

//go:embed index.html
var page []byte

//go:embed app.js
var script []byte

type config struct{ AuthURL, AppURL, TenantID string }

func origin(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && (u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")))
}
func newApp(c config, client *http.Client) (http.Handler, error) {
	if !origin(c.AuthURL) || !origin(c.AppURL) {
		return nil, errors.New("AUTH_URL and APP_PUBLIC_URL must be origins; HTTP is allowed only on loopback")
	}
	if _, e := uuid.Parse(c.TenantID); e != nil {
		return nil, errors.New("EXPECTED_TENANT_ID must be the workspace UUID from /me")
	}
	safeClient := *client
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	upstream := func(r *http.Request, path string, body []byte) (*http.Response, error) {
		req, e := http.NewRequestWithContext(r.Context(), r.Method, c.AuthURL+"/api/v1/auth/"+path, bytes.NewReader(body))
		if e != nil {
			return nil, e
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", r.Header.Get("Authorization"))
		// Never forward cookies, caller identity, Origin or untrusted proxy headers.
		return safeClient.Do(req)
	}
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})
	m.HandleFunc("GET /app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Write(script)
	})
	m.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"account_url": c.AuthURL + "/account"})
	})
	for _, path := range []string{"login", "mfa/verify", "refresh", "logout"} {
		m.HandleFunc("POST /api/auth/"+path, func(w http.ResponseWriter, r *http.Request) {
			body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
			if e != nil {
				http.Error(w, "Request too large", 413)
				return
			}
			response, e := upstream(r, path, body)
			if e != nil {
				http.Error(w, "Authentication unavailable", 503)
				return
			}
			defer response.Body.Close()
			raw, e := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
			if e != nil || len(raw) > 64*1024 || !json.Valid(raw) {
				http.Error(w, "Invalid auth response", 503)
				return
			}
			if response.StatusCode >= 300 && response.StatusCode < 400 {
				http.Error(w, "Unexpected auth redirect", 503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(response.StatusCode)
			w.Write(raw)
		})
	}
	m.HandleFunc("GET /api/projects", func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		if !strings.HasPrefix(bearer, "Bearer ") || len(strings.TrimPrefix(bearer, "Bearer ")) < 1 {
			http.Error(w, "Sign in first", 401)
			return
		}
		response, e := upstream(r, "me", nil)
		if e != nil {
			http.Error(w, "Authentication unavailable", 503)
			return
		}
		defer response.Body.Close()
		if response.StatusCode == 401 || response.StatusCode == 403 {
			http.Error(w, "Sign in again", 401)
			return
		}
		if response.StatusCode != 200 {
			http.Error(w, "Authentication unavailable", 503)
			return
		}
		var envelope struct{ Data map[string]any }
		raw, e := io.ReadAll(io.LimitReader(response.Body, 4097))
		if e != nil || len(raw) > 4096 || json.Unmarshal(raw, &envelope) != nil {
			http.Error(w, "Invalid identity", 503)
			return
		}
		user, _ := envelope.Data["id"].(string)
		tenant, _ := envelope.Data["tenant_id"].(string)
		if _, e = uuid.Parse(user); e != nil {
			http.Error(w, "Invalid identity", 503)
			return
		}
		if tenant != c.TenantID {
			http.Error(w, "Wrong workspace", 403)
			return
		}
		// In an existing product, query its own DB with BOTH tenant_id and user_id.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"user_id": user, "tenant_id": tenant, "projects": []map[string]string{{"name": "Your example project", "owner_id": user, "tenant_id": tenant}}})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if value := r.Header.Get("Origin"); value != "" && value != c.AppURL {
			http.Error(w, "Origin denied", 403)
			return
		}
		m.ServeHTTP(w, r)
	}), nil
}
func main() {
	c := config{strings.TrimRight(os.Getenv("AUTH_URL"), "/"), strings.TrimRight(os.Getenv("APP_PUBLIC_URL"), "/"), os.Getenv("EXPECTED_TENANT_ID")}
	handler, e := newApp(c, &http.Client{Timeout: 5 * time.Second})
	if e != nil {
		log.Fatal(e)
	}
	address := os.Getenv("APP_LISTEN_ADDR")
	if address == "" {
		address = "127.0.0.1:8090"
	}
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	log.Printf("Example product listening on %s", address)
	log.Fatal(server.ListenAndServe())
}
