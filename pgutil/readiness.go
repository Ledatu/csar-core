package pgutil

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ledatu/csar-core/health"
)

// PoolReadiness checks a service-owned pool without exposing connection details.
// It is suitable for a module's Readiness hook, including before Start/after Stop.
func PoolReadiness(pool *pgxpool.Pool) health.CheckStatus {
	if pool == nil {
		return health.CheckStatus{Status: "fail", Detail: "database not started"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pool.Ping(ctx); err != nil {
		return health.CheckStatus{Status: "fail", Detail: "database unavailable"}
	}
	return health.CheckStatus{Status: "ok"}
}
