//go:build restore

package service

import (
	"context"
	"encoding/base32"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"testing"
)

func TestRestoredRecords(t *testing.T) {
	if os.Getenv("AUTH_ISOLATED_TEST") != "1" {
		t.Fatal("isolated runner required")
	}
	db, e := pgxpool.New(context.Background(), os.Getenv("AUTH_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	rows, e := db.Query(context.Background(), "SELECT mfa_secret FROM auth_users WHERE mfa_secret IS NOT NULL")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	c := Config{ActiveKey: "v2", Keys: map[string][]byte{"v2": []byte(strings.Repeat("y", 32))}}
	count := 0
	knownFixture := false
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			t.Fatal(e)
		}
		plain, e := c.decrypt(raw)
		if e != nil {
			t.Fatal("restored factor or key rotation invalid", e)
		}
		seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(plain)
		if err != nil || len(seed) < 10 {
			t.Fatal("restored factor is not a valid TOTP seed")
		}
		knownFixture = knownFixture || plain == "JBSWY3DPEHPK3PXP"
		count++
	}
	if rows.Err() != nil || count == 0 || !knownFixture {
		t.Fatal("no restored factors", rows.Err())
	}
}
