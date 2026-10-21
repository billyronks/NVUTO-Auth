//go:build integration

package service

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSMTPTransport(t *testing.T) {
	for _, mode := range []string{"trusted-starttls", "authenticated-starttls", "rejected-credentials", "no-starttls", "untrusted-certificate"} {
		t.Run(mode, func(t *testing.T) {
			private, e := rsa.GenerateKey(rand.Reader, 2048)
			if e != nil {
				t.Fatal(e)
			}
			certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic SMTP"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, e := x509.CreateCertificate(rand.Reader, certificate, certificate, &private.PublicKey, private)
			if e != nil {
				t.Fatal(e)
			}
			parsed, _ := x509.ParseCertificate(der)
			pool := x509.NewCertPool()
			pool.AddCert(parsed)
			cert, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)}))
			if e != nil {
				t.Fatal(e)
			}
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			received := make(chan string, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				connection, e := listener.Accept()
				if e != nil {
					return
				}
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(connection)
				write := func(line string) { _, _ = fmt.Fprint(connection, line) }
				write("220 synthetic SMTP\r\n")
				secure := false
				authenticated := false
				for {
					line, e := reader.ReadString('\n')
					if e != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						if !secure && mode != "no-starttls" {
							write("250-synthetic\r\n250 STARTTLS\r\n")
						} else if secure {
							write("250-synthetic\r\n250 AUTH PLAIN\r\n")
						} else {
							write("250 synthetic\r\n")
						}
					case strings.HasPrefix(line, "STARTTLS"):
						write("220 begin TLS\r\n")
						wrapped := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
						if wrapped.Handshake() != nil {
							return
						}
						connection = wrapped
						reader = bufio.NewReader(connection)
						secure = true
					case strings.HasPrefix(line, "AUTH PLAIN "):
						payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(line, "AUTH PLAIN ")))
						if !secure || err != nil || string(payload) != "\x00synthetic-user\x00synthetic-password" || mode == "rejected-credentials" {
							write("535 authentication failed\r\n")
						} else {
							authenticated = true
							write("235 authenticated\r\n")
						}
					case strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"):
						if (mode == "authenticated-starttls" || mode == "rejected-credentials") && !authenticated {
							write("530 authentication required\r\n")
							continue
						}
						write("250 OK\r\n")
					case strings.HasPrefix(line, "DATA"):
						write("354 continue\r\n")
						var body strings.Builder
						for {
							line, e = reader.ReadString('\n')
							if e != nil {
								return
							}
							if line == ".\r\n" {
								break
							}
							body.WriteString(line)
						}
						received <- body.String()
						write("250 accepted\r\n")
					case strings.HasPrefix(line, "QUIT"):
						write("221 bye\r\n")
						return
					default:
						write("500 unsupported\r\n")
					}
				}
			}()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			s := &Service{Config: Config{SMTPHost: host, SMTPPort: port, MailFrom: "auth@example.test"}}
			if mode == "authenticated-starttls" || mode == "rejected-credentials" {
				s.Config.SMTPUser = "synthetic-user"
				s.Config.SMTPPassword = "synthetic-password"
			}
			if mode != "untrusted-certificate" {
				s.Config.SMTPRootCAs = pool
			}
			e = s.sendMail(context.Background(), "recipient@example.test", "Synthetic account message")
			if mode == "trusted-starttls" || mode == "authenticated-starttls" {
				if e != nil {
					t.Fatal(e)
				}
				select {
				case body := <-received:
					if !strings.Contains(body, "Synthetic account message") {
						t.Fatal("message missing")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("message not received")
				}
			} else if e == nil {
				t.Fatal("insecure SMTP transport accepted")
			}
			<-done
		})
	}
}
