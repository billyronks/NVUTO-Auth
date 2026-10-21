// This is a backend integration example. Apply your own resource authorization.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	base := os.Getenv("AUTH_URL")
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		log.Fatal("AUTH_URL must be the trusted HTTPS auth origin")
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !strings.HasPrefix(token, "Bearer ") {
			http.Error(w, "Unauthorized", 401)
			return
		}
		request, e := http.NewRequestWithContext(r.Context(), "GET", strings.TrimRight(base, "/")+"/api/v1/auth/me", nil)
		if e != nil {
			http.Error(w, "Unavailable", 503)
			return
		}
		request.Header.Set("Authorization", token)
		response, e := client.Do(request)
		if e != nil {
			http.Error(w, "Unavailable", 503)
			return
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			http.Error(w, "Unauthorized", 401)
			return
		}
		var envelope struct{ Data map[string]any }
		if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&envelope) != nil || envelope.Data["id"] == nil {
			http.Error(w, "Unavailable", 503)
			return
		}
		if envelope.Data["tenant_id"] != os.Getenv("EXPECTED_TENANT_ID") {
			http.Error(w, "Forbidden", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"user_id": envelope.Data["id"], "message": "Apply product-specific resource authorization here."})
	})
	server := &http.Server{Addr: "127.0.0.1:8090", Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	log.Fatal(server.ListenAndServe())
}
