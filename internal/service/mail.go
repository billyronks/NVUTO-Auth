package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/jackc/pgx/v5"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

func (s *Service) DeliverOne(ctx context.Context) (bool, error) {
	done := false
	_, err := transact(ctx, s.DB, func(tx pgx.Tx) (any, error) {
		var id int64
		var recipient, body string
		e := tx.QueryRow(ctx, "SELECT id,recipient,encrypted_body FROM auth_outbox WHERE delivered_at IS NULL AND attempts<10 AND next_attempt<=now() ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1").Scan(&id, &recipient, &body)
		if e == pgx.ErrNoRows {
			return nil, nil
		}
		if e != nil {
			return nil, e
		}
		done = true
		text, e := s.Config.decrypt(body)
		if e == nil {
			e = s.sendMail(ctx, recipient, text)
		}
		if e != nil {
			_, err := tx.Exec(ctx, "UPDATE auth_outbox SET attempts=attempts+1,next_attempt=now()+interval '1 minute' * LEAST(60,power(2,attempts)::int) WHERE id=$1", id)
			return nil, err
		}
		_, e = tx.Exec(ctx, "UPDATE auth_outbox SET delivered_at=now(),encrypted_body='' WHERE id=$1", id)
		return nil, e
	})
	return done, err
}
func (s *Service) sendMail(ctx context.Context, to, body string) error {
	from, e := mail.ParseAddress(s.Config.MailFrom)
	if e != nil {
		return e
	}
	recipient, e := mail.ParseAddress(to)
	if e != nil {
		return e
	}
	conn, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(s.Config.SMTPHost, s.Config.SMTPPort))
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	client, e := smtp.NewClient(conn, s.Config.SMTPHost)
	if e != nil {
		return e
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); !ok {
		return fmt.Errorf("SMTP STARTTLS required")
	}
	if e = client.StartTLS(&tls.Config{ServerName: s.Config.SMTPHost, MinVersion: tls.VersionTLS12, RootCAs: s.Config.SMTPRootCAs}); e != nil {
		return e
	}
	if s.Config.SMTPUser != "" {
		if e = client.Auth(smtp.PlainAuth("", s.Config.SMTPUser, s.Config.SMTPPassword, s.Config.SMTPHost)); e != nil {
			return e
		}
	}
	if e = client.Mail(from.Address); e != nil {
		return e
	}
	if e = client.Rcpt(recipient.Address); e != nil {
		return e
	}
	out, e := client.Data()
	if e != nil {
		return e
	}
	message := "From: " + from.String() + "\r\nTo: " + recipient.String() + "\r\nSubject: NVUTO Auth account security\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + strings.ReplaceAll(body, "\r\n", "\n")
	if _, e = out.Write([]byte(message)); e != nil {
		return e
	}
	if e = out.Close(); e != nil {
		return e
	}
	return client.Quit()
}
func (s *Service) MailWorker(ctx context.Context) {
	timer := time.NewTicker(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			work, cancel := context.WithTimeout(ctx, 20*time.Second)
			_, _ = s.DeliverOne(work)
			cancel()
		}
	}
}
