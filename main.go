package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/billyronks/NVUTO-Auth/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/term"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	c, e := service.LoadConfig()
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	connect, cancelConnect := context.WithTimeout(ctx, 10*time.Second)
	defer cancelConnect()
	db, e := pgxpool.New(connect, c.DatabaseURL)
	if e != nil {
		return errors.New("invalid database configuration")
	}
	defer db.Close()
	if e = db.Ping(connect); e != nil {
		return errors.New("database unavailable")
	}
	s := &service.Service{DB: db, Config: c}
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	switch command {
	case "migrate":
		tx, e := db.Begin(ctx)
		if e != nil {
			return e
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(728104292)"); e != nil {
			return e
		}
		var legacy bool
		if e = tx.QueryRow(ctx, "SELECT to_regclass('public.users') IS NOT NULL").Scan(&legacy); e != nil {
			return e
		}
		if legacy {
			return errors.New("use a fresh dedicated auth database; unrelated tables already exist")
		}
		if _, e = tx.Exec(ctx, service.Schema); e != nil {
			return errors.New("schema migration failed")
		}
		if role := os.Getenv("RUNTIME_DATABASE_ROLE"); role != "" {
			id := pgx.Identifier{role}.Sanitize()
			for _, q := range []string{"GRANT USAGE ON SCHEMA public TO " + id, "GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO " + id, "GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO " + id, "REVOKE UPDATE,DELETE ON auth_audit FROM " + id, "REVOKE INSERT,UPDATE,DELETE ON auth_schema FROM " + id} {
				if _, e = tx.Exec(ctx, q); e != nil {
					return errors.New("runtime role grant failed")
				}
			}
		}
		return tx.Commit(ctx)
	case "bootstrap":
		fmt.Fprintln(os.Stderr, "Read initial owner password from stdin (15-72 bytes); email verification is still required.")
		var password string
		if term.IsTerminal(int(os.Stdin.Fd())) {
			value, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return errors.New("unable to read password")
			}
			password = string(value)
		} else {
			reader := bufio.NewReader(os.Stdin)
			value, err := reader.ReadString('\n')
			if err != nil && len(value) == 0 {
				return errors.New("password required on stdin")
			}
			password = value
		}
		return s.Bootstrap(ctx, os.Getenv("BOOTSTRAP_TENANT"), os.Getenv("BOOTSTRAP_EMAIL"), os.Getenv("BOOTSTRAP_NAME"), strings.TrimRight(password, "\r\n"))
	case "cleanup":
		return s.Cleanup(ctx)
	case "rotate-encryption":
		return s.RotateEncryption(ctx)
	case "serve":
		var privileged bool
		if e = db.QueryRow(ctx, "SELECT rolsuper OR rolbypassrls OR pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid='auth_users'::regclass),'MEMBER') FROM pg_roles WHERE rolname=current_user").Scan(&privileged); e != nil {
			return e
		}
		if privileged {
			return errors.New("runtime database role must not be superuser or BYPASSRLS")
		}
		var version int
		if e = db.QueryRow(ctx, "SELECT version FROM auth_schema WHERE version=1").Scan(&version); e != nil {
			return errors.New("run migrations with the migration role first")
		}
		workerCtx, stopWorker := context.WithCancel(ctx)
		defer stopWorker()
		done := make(chan struct{})
		go func() { defer close(done); s.MailWorker(workerCtx) }()
		server := &http.Server{Addr: c.Listen, Handler: s.Routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 25 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
		serveErr := make(chan error, 1)
		go func() { serveErr <- server.ListenAndServe() }()
		log.Print("NVUTO Auth listening")
		select {
		case <-ctx.Done():
		case e = <-serveErr:
			if !errors.Is(e, http.ErrServerClosed) {
				return e
			}
		}
		shutdown, closeShutdown := context.WithTimeout(context.Background(), 30*time.Second)
		defer closeShutdown()
		e = server.Shutdown(shutdown)
		stopWorker()
		<-done
		return e
	default:
		return errors.New("command must be serve, migrate, bootstrap, cleanup, or rotate-encryption")
	}
}
