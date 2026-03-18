package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ledatu/csar-core/pgutil"
)

var migrations = []pgutil.Migration{
	{
		Name: "001_audit_events",
		Up: `
CREATE TABLE IF NOT EXISTS audit_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    target_type  TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    scope_type   TEXT NOT NULL,
    scope_id     TEXT NOT NULL DEFAULT '',
    before_state JSONB,
    after_state  JSONB,
    metadata     JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_scope
    ON audit_events (scope_type, scope_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor
    ON audit_events (actor, created_at DESC);
`,
	},
}

// PostgresStore implements Store backed by PostgreSQL.
type PostgresStore struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewPostgresStore creates a new audit store using the provided pool.
func NewPostgresStore(pool *pgxpool.Pool, logger *slog.Logger) *PostgresStore {
	return &PostgresStore{pool: pool, logger: logger}
}

// Migrate runs audit-specific schema migrations.
func (s *PostgresStore) Migrate(ctx context.Context) error {
	return pgutil.RunMigrations(ctx, s.pool, "audit_migrations", migrations, s.logger)
}

func (s *PostgresStore) Record(ctx context.Context, event *Event) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_events (actor, action, target_type, target_id, scope_type, scope_id, before_state, after_state, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		event.Actor, event.Action, event.TargetType, event.TargetID,
		event.ScopeType, event.ScopeID,
		nullableJSON(event.BeforeState), nullableJSON(event.AfterState), nullableJSON(event.Metadata),
	)
	if err != nil {
		return fmt.Errorf("recording audit event: %w", err)
	}
	return nil
}

func (s *PostgresStore) List(ctx context.Context, filter *ListFilter) (*ListResult, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	query := `SELECT id, actor, action, target_type, target_id, scope_type, scope_id,
	                  before_state, after_state, metadata, created_at
	           FROM audit_events WHERE 1=1`
	args := []any{}
	idx := 1

	if filter.ScopeType != "" {
		query += fmt.Sprintf(" AND scope_type = $%d", idx)
		args = append(args, filter.ScopeType)
		idx++
	}
	if filter.ScopeID != "" {
		query += fmt.Sprintf(" AND scope_id = $%d", idx)
		args = append(args, filter.ScopeID)
		idx++
	}
	if filter.Actor != "" {
		query += fmt.Sprintf(" AND actor = $%d", idx)
		args = append(args, filter.Actor)
		idx++
	}
	if filter.Action != "" {
		query += fmt.Sprintf(" AND action = $%d", idx)
		args = append(args, filter.Action)
		idx++
	}
	if filter.TargetType != "" {
		query += fmt.Sprintf(" AND target_type = $%d", idx)
		args = append(args, filter.TargetType)
		idx++
	}
	if filter.Since != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *filter.Since)
		idx++
	}
	if filter.Until != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *filter.Until)
		idx++
	}
	if filter.Cursor != "" {
		if cursorTime, cursorID, err := decodeCursor(filter.Cursor); err == nil {
			query += fmt.Sprintf(" AND (created_at < $%d OR (created_at = $%d AND id < $%d))",
				idx, idx, idx+1)
			args = append(args, cursorTime, cursorID)
			idx += 2
		}
	}

	query += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d", idx)
	args = append(args, limit+1)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing audit events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.TargetType, &e.TargetID,
			&e.ScopeType, &e.ScopeID, &e.BeforeState, &e.AfterState, &e.Metadata, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning audit event: %w", err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := &ListResult{}
	if len(events) > limit {
		events = events[:limit]
		last := events[len(events)-1]
		result.NextCursor = encodeCursor(last.CreatedAt, last.ID)
	}
	result.Events = events
	return result, nil
}

func nullableJSON(data json.RawMessage) any {
	if len(data) == 0 {
		return nil
	}
	return data
}

func encodeCursor(t time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(t.Format(time.RFC3339Nano) + "|" + id),
	)
}

func decodeCursor(cursor string) (time.Time, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", err
	}
	parts := strings.SplitN(string(b), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, "", fmt.Errorf("invalid cursor format")
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", err
	}
	return t, parts[1], nil
}
