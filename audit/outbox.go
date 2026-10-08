package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ledatu/csar-core/pgutil"
)

const (
	outboxLease       = 60 * time.Second
	outboxDBTimeout   = 5 * time.Second
	outboxSendTimeout = 30 * time.Second
	maxOutboxPayload  = 256 << 10
)

var ErrOutboxLeaseLost = errors.New("audit outbox lease lost")

// PGOutbox persists events in the SAME database transaction as a business write.
// Each service claims only its own rows, even when several services share a DB.
type PGOutbox struct {
	pool    *pgxpool.Pool
	service string
}

func NewPGOutbox(pool *pgxpool.Pool, service string) (*PGOutbox, error) {
	if pool == nil || service == "" {
		return nil, errors.New("audit outbox requires pool and service")
	}
	return &PGOutbox{pool: pool, service: service}, nil
}

// Migrate serializes concurrent startup migrations with a transaction-scoped lock.
func (o *PGOutbox) Migrate(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	return pgutil.WithTx(ctx, o.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(839106410823)`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS csar_audit_outbox (
 id uuid PRIMARY KEY,
 service text NOT NULL,
 payload bytea NOT NULL CHECK (octet_length(payload) <= 262144),
 enqueued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 next_attempt timestamptz NOT NULL DEFAULT clock_timestamp(),
 attempts bigint NOT NULL DEFAULT 0,
 lease_token uuid,
 lease_until timestamptz,
 CHECK ((lease_token IS NULL) = (lease_until IS NULL))
);
CREATE INDEX IF NOT EXISTS csar_audit_outbox_due ON csar_audit_outbox(service, next_attempt, enqueued_at);`)
		return err
	})
}

// EnqueueTx must use the caller's business transaction. A failure must roll it back.
// Prepare once before calling when retaining identity across a transaction retry.
func (o *PGOutbox) EnqueueTx(ctx context.Context, tx pgx.Tx, event *Event) error {
	prepared, err := PrepareEvent(event)
	if err != nil {
		return err
	}
	if prepared.Service != "" && prepared.Service != o.service {
		return errors.New("audit outbox service mismatch")
	}
	prepared.Service = o.service
	if err := ValidateEvent(prepared); err != nil {
		return err
	}
	payload, err := json.Marshal(prepared)
	if err != nil {
		return err
	}
	if len(payload) > maxOutboxPayload {
		return errors.New("audit outbox payload too large")
	}
	tag, err := tx.Exec(ctx, `INSERT INTO csar_audit_outbox(id, service, payload) VALUES ($1,$2,$3)
 ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id
 WHERE csar_audit_outbox.service=EXCLUDED.service AND csar_audit_outbox.payload=EXCLUDED.payload`, prepared.ID, o.service, payload)
	if err != nil {
		return fmt.Errorf("enqueue audit outbox: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("audit outbox event identity conflict")
	}
	return nil
}

type outboxClaim struct {
	id       string
	token    string
	payload  []byte
	attempts int64
}

func (o *PGOutbox) claim(ctx context.Context) (*outboxClaim, error) {
	ctx, cancel := context.WithTimeout(ctx, outboxDBTimeout)
	defer cancel()
	row := &outboxClaim{token: uuid.NewString()}
	err := o.pool.QueryRow(ctx, `WITH candidate AS (
 SELECT id FROM csar_audit_outbox WHERE service=$1 AND next_attempt<=clock_timestamp()
 AND (lease_until IS NULL OR lease_until<=clock_timestamp())
 ORDER BY next_attempt,enqueued_at,id FOR UPDATE SKIP LOCKED LIMIT 1
) UPDATE csar_audit_outbox AS o SET lease_token=$2,lease_until=clock_timestamp()+$3::bigint*interval '1 second',attempts=o.attempts+1
 FROM candidate WHERE o.id=candidate.id RETURNING o.id::text,o.payload,o.attempts`, o.service, row.token, int64(outboxLease/time.Second)).Scan(&row.id, &row.payload, &row.attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return row, nil
}

func (o *PGOutbox) finish(ctx context.Context, claim *outboxClaim, delivered bool) error {
	ctx, cancel := context.WithTimeout(ctx, outboxDBTimeout)
	defer cancel()
	query := `DELETE FROM csar_audit_outbox WHERE id=$1 AND lease_token=$2 AND lease_until>clock_timestamp()`
	args := []any{claim.id, claim.token}
	if !delivered {
		query = `UPDATE csar_audit_outbox SET next_attempt=clock_timestamp()+$3::bigint*interval '1 second',lease_token=NULL,lease_until=NULL
 WHERE id=$1 AND lease_token=$2 AND lease_until>clock_timestamp()`
		args = append(args, retrySeconds(claim.attempts))
	}
	tag, err := o.pool.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrOutboxLeaseLost
	}
	return nil
}

func retrySeconds(attempts int64) int64 {
	if attempts > 5 {
		return 30
	}
	if attempts < 1 {
		return 1
	}
	return 1 << (attempts - 1)
}

// DeliverOne retains the row on uncertainty. Transport must report durable ingest
// acceptance, not async enqueue. A crashed/expired worker cannot finish a new lease.
func (o *PGOutbox) DeliverOne(ctx context.Context, transport Transport) (bool, error) {
	if transport == nil {
		return false, errors.New("audit outbox transport required")
	}
	claim, err := o.claim(ctx)
	if err != nil || claim == nil {
		return false, err
	}
	var event Event
	sendErr := json.Unmarshal(claim.payload, &event)
	if sendErr == nil {
		sendCtx, cancel := context.WithTimeout(ctx, outboxSendTimeout)
		sendErr = transport.Send(sendCtx, []*Event{&event})
		cancel()
	}
	// Cancellation may prevent releasing the lease; expiry safely makes it replayable.
	if err := o.finish(ctx, claim, sendErr == nil); err != nil {
		return true, err
	}
	if sendErr != nil {
		return true, errors.New("audit outbox delivery failed; retained for retry")
	}
	return true, nil
}

// Run uses one bounded send per replica. Send (30s) plus DB finish (5s) fit inside
// the 60s lease; no network call runs inside a business/claim transaction.
func (o *PGOutbox) Run(ctx context.Context, transport Transport, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	for ctx.Err() == nil {
		worked, err := o.DeliverOne(ctx, transport)
		if err != nil && ctx.Err() == nil {
			logger.Warn("audit outbox relay failed; pending events retained")
		}
		if worked && err == nil {
			continue
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

type OutboxBacklog struct {
	Count     int64
	OldestAge time.Duration
}

// Backlog includes delayed/leased rows: count zero is the only drained proof.
func (o *PGOutbox) Backlog(ctx context.Context) (OutboxBacklog, error) {
	ctx, cancel := context.WithTimeout(ctx, outboxDBTimeout)
	defer cancel()
	var backlog OutboxBacklog
	var age float64
	err := o.pool.QueryRow(ctx, `SELECT count(*),COALESCE(GREATEST(extract(epoch FROM clock_timestamp()-min(enqueued_at)),0),0)::float8
 FROM csar_audit_outbox WHERE service=$1`, o.service).Scan(&backlog.Count, &age)
	backlog.OldestAge = time.Duration(age * float64(time.Second))
	return backlog, err
}
