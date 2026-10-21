package service

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
)

func (c Config) trusted(addr netip.Addr) bool {
	for _, p := range c.TrustedProxies {
		if p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}
func (s *Service) clientIP(r *http.Request) (string, error) {
	peer, e := netip.ParseAddrPort(r.RemoteAddr)
	if e != nil {
		return "", e
	}
	current := peer.Addr().Unmap()
	if !s.Config.trusted(current) {
		return current.String(), nil
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if len(forwarded) > 2048 {
		return "", errors.New("proxy chain too long")
	}
	parts := strings.Split(forwarded, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if !s.Config.trusted(current) {
			break
		}
		next, e := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if e != nil {
			return "", errors.New("invalid proxy chain")
		}
		current = next.Unmap()
	}
	return current.String(), nil
}
