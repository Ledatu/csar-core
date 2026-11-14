package pgutil

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPoolReadinessMissingAndClosedAreSafe(t *testing.T) {
	if PoolReadiness(nil).Status != "fail" {
		t.Fatal("missing pool ready")
	}
	pool, err := pgxpool.New(context.Background(), "postgres://private-user:private-value@127.0.0.1:1/example?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	got := PoolReadiness(pool)
	if got.Status != "fail" || got.Detail != "database unavailable" {
		t.Fatalf("unsafe readiness: %+v", got)
	}
}
