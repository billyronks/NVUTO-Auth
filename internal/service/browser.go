package service

import (
	_ "embed"
	"net/http"
)

//go:embed account.html
var accountHTML []byte

//go:embed account.js
var accountJS []byte

func accountPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
	_, _ = w.Write(accountHTML)
}
func accountScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(accountJS)
}
