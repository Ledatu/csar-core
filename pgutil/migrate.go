package pgutil

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration holds a single schema migration step.
type Migration struct {
	Name string // unique identifier, e.g. "001_initial"
	Up   string // SQL to apply
}

// RunMigrations creates a tracking table and applies pending migrations.
//
// Each migration is applied in its own transaction. The tableName parameter
// allows different services to use distinct tracking tables in the same
// database (e.g. "authn_schema_migrations", "authz_schema_migrations").
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, tableName string, migrations []Migration, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	// Create migrations tracking table.
	_, err := pool.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			name       TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`, quoteIdent(tableName)))
	if err != nil {
		return fmt.Errorf("creating migrations table: %w", err)
	}

	for _, m := range migrations {
		// Check if already applied.
		var exists bool
		err := pool.QueryRow(ctx,
			fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE name = $1)", quoteIdent(tableName)), m.Name,
		).Scan(&exists)
		if err != nil {
			return fmt.Errorf("checking migration %s: %w", m.Name, err)
		}
		if exists {
			continue
		}

		// Apply migration in a transaction.
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("beginning migration %s: %w", m.Name, err)
		}

		if _, err := tx.Exec(ctx, m.Up); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("applying migration %s: %w", m.Name, err)
		}

		if _, err := tx.Exec(ctx, fmt.Sprintf("INSERT INTO %s (name) VALUES ($1)", quoteIdent(tableName)), m.Name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("recording migration %s: %w", m.Name, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("committing migration %s: %w", m.Name, err)
		}

		logger.Info("applied migration", "name", m.Name)
	}

	return nil
}

// quoteIdent wraps an identifier in double-quotes for safe use in SQL.
// This prevents SQL injection via table names.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
