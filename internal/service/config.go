package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"unicode/utf8"
)

type Config struct {
	TrustedProxies                                       []netip.Prefix
	SMTPRootCAs                                          *x509.CertPool
	DatabaseURL, PublicURL, Listen, ActiveKey            string
	Keys                                                 map[string][]byte
	Registration                                         bool
	SMTPHost, SMTPPort, SMTPUser, SMTPPassword, MailFrom string
}

func LoadConfig() (Config, error) {
	c := Config{DatabaseURL: os.Getenv("DATABASE_URL"), PublicURL: os.Getenv("PUBLIC_URL"), Listen: os.Getenv("LISTEN_ADDR"), ActiveKey: os.Getenv("AUTH_ACTIVE_KEY"), Keys: map[string][]byte{}, Registration: os.Getenv("REGISTRATION_MODE") == "public", SMTPHost: os.Getenv("SMTP_HOST"), SMTPPort: os.Getenv("SMTP_PORT"), SMTPUser: os.Getenv("SMTP_USER"), SMTPPassword: os.Getenv("SMTP_PASSWORD"), MailFrom: os.Getenv("MAIL_FROM")}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8081"
	}
	if c.SMTPPort == "" {
		c.SMTPPort = "587"
	}
	for _, entry := range strings.Split(os.Getenv("AUTH_ENCRYPTION_KEYS"), ",") {
		parts := strings.Split(entry, ":")
		if len(parts) != 2 || parts[0] == "" {
			return c, errors.New("AUTH_ENCRYPTION_KEYS requires key-id:64-hex pairs")
		}
		key, e := hex.DecodeString(parts[1])
		if e != nil || len(key) != 32 {
			return c, errors.New("encryption keys must be 256-bit hexadecimal")
		}
		if _, ok := c.Keys[parts[0]]; ok {
			return c, errors.New("duplicate encryption key ID")
		}
		c.Keys[parts[0]] = key
	}
	if len(c.Keys[c.ActiveKey]) != 32 {
		return c, errors.New("AUTH_ACTIVE_KEY must identify a configured key")
	}
	if c.DatabaseURL == "" {
		return c, errors.New("DATABASE_URL required")
	}
	u, e := url.Parse(c.PublicURL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return c, errors.New("PUBLIC_URL must be an origin")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
		return c, errors.New("PUBLIC_URL requires HTTPS except loopback development")
	}
	mode := os.Getenv("REGISTRATION_MODE")
	if mode != "" && mode != "invite" && mode != "public" {
		return c, errors.New("REGISTRATION_MODE must be invite or public")
	}
	if c.SMTPHost == "" || c.MailFrom == "" {
		return c, errors.New("SMTP_HOST and MAIL_FROM required")
	}
	if (c.SMTPUser == "") != (c.SMTPPassword == "") {
		return c, errors.New("SMTP_USER and SMTP_PASSWORD must be configured together")
	}
	if _, e := mail.ParseAddress(c.MailFrom); e != nil {
		return c, errors.New("MAIL_FROM must be a valid mailbox")
	}
	for _, raw := range strings.Split(os.Getenv("TRUSTED_PROXIES"), ",") {
		if raw == "" {
			continue
		}
		prefix, e := netip.ParsePrefix(raw)
		if e != nil {
			return c, errors.New("TRUSTED_PROXIES requires CIDR addresses")
		}
		c.TrustedProxies = append(c.TrustedProxies, prefix)
	}
	if file := os.Getenv("SMTP_CA_FILE"); file != "" {
		pem, e := os.ReadFile(file)
		if e != nil {
			return c, errors.New("SMTP_CA_FILE unreadable")
		}
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return c, errors.New("SMTP_CA_FILE contains no certificate")
		}
		c.SMTPRootCAs = pool
	}
	dbURL, e := url.Parse(c.DatabaseURL)
	if e != nil || dbURL.Scheme != "postgres" && dbURL.Scheme != "postgresql" || dbURL.Host == "" {
		return c, errors.New("DATABASE_URL must be a PostgreSQL URL")
	}
	host := dbURL.Hostname()
	local := host == "127.0.0.1" || host == "localhost" || host == "db"
	if !local && dbURL.Query().Get("sslmode") != "verify-full" {
		return c, errors.New("remote database requires sslmode=verify-full")
	}
	return c, nil
}

func randomToken() string {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func digest(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func (c Config) encrypt(s string) (string, error) {
	b, e := aes.NewCipher(c.Keys[c.ActiveKey])
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return "", e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return "", e
	}
	return c.ActiveKey + ":" + base64.RawURLEncoding.EncodeToString(g.Seal(n, n, []byte(s), []byte(c.ActiveKey))), nil
}
func (c Config) decrypt(s string) (string, error) {
	p := strings.Split(s, ":")
	if len(p) != 2 || len(c.Keys[p[0]]) != 32 {
		return "", errors.New("unknown encryption key")
	}
	b, e := aes.NewCipher(c.Keys[p[0]])
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return "", e
	}
	raw, e := base64.RawURLEncoding.DecodeString(p[1])
	if e != nil || len(raw) < g.NonceSize()+g.Overhead() {
		return "", errors.New("malformed ciphertext")
	}
	v, e := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], []byte(p[0]))
	return string(v), e
}
func passwordPolicy(p string) error {
	if !utf8.ValidString(p) || utf8.RuneCountInString(p) < 15 || len(p) > 72 {
		return fmt.Errorf("password must contain at least 15 characters and at most 72 UTF-8 bytes")
	}
	return nil
}
