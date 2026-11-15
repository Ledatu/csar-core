package pgutil

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestReadOnlyPoolOptions(t *testing.T) {
	var c poolConfig
	WithReadOnly()(&c)
	WithMinConns(0)(&c)
	if !c.readOnly || !c.minConnsSet || c.minConns != 0 {
		t.Fatal("read-only options not applied")
	}
}

func TestReadOnlyPoolRejectsWritesLocally(t *testing.T) {
	dsn := os.Getenv("OZON_SOURCE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("local PostgreSQL fixture not configured")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "127.0.0.1" || u.Path != "/ozsource" {
		t.Fatal("requires disposable loopback ozsource database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := NewPool(ctx, dsn, WithReadOnly(), WithMaxConns(2), WithMinConns(0), WithStatementTimeout(15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var value string
	if err = pool.QueryRow(ctx, "SHOW transaction_read_only").Scan(&value); err != nil || value != "on" {
		t.Fatal("reader session not read-only", value, err)
	}
	if err = pool.QueryRow(ctx, "SHOW statement_timeout").Scan(&value); err != nil || value != "15s" {
		t.Fatal("server statement bound not applied", value, err)
	}
	if _, err = pool.Exec(ctx, "CREATE TABLE oz567_unexpected_write(id integer)"); err == nil {
		t.Fatal("reader accepted DDL")
	}
}
