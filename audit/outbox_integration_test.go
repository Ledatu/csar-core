package audit

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ledatu/csar-core/pgutil"
)

func outboxFixture(t *testing.T) (*PGOutbox, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("AUDIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated localhost outbox database not configured")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if (cfg.ConnConfig.Host != "localhost" && cfg.ConnConfig.Host != "127.0.0.1") || cfg.ConnConfig.Database != "csar_audit_test" || len(cfg.ConnConfig.Fallbacks) > 0 {
		t.Fatal("outbox tests require isolated localhost csar_audit_test without fallback hosts")
	}
	ctx := context.Background()
	admin, err := pgxpool.NewWithConfig(ctx, cfg.Copy())
	if err != nil {
		t.Fatal(err)
	}
	schema := "outbox_test_" + uuid.New().String()[:8]
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = ident
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, err := admin.Exec(ctx, "DROP SCHEMA "+ident+" CASCADE")
		admin.Close()
		if err != nil {
			t.Error(err)
		}
	})
	outbox, err := NewPGOutbox(pool, "test-producer")
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE business(id int PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	return outbox, pool
}

func outboxEvent(t *testing.T) *Event {
	t.Helper()
	e, err := PrepareEvent(&Event{Actor: "user", Action: "change", TargetType: "test", ScopeType: "platform"})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func enqueueTest(t *testing.T, o *PGOutbox, e *Event) {
	t.Helper()
	if err := pgutil.WithTx(context.Background(), o.pool, func(tx pgx.Tx) error { return o.EnqueueTx(context.Background(), tx, e) }); err != nil {
		t.Fatal(err)
	}
}

func TestOutboxBusinessAndEventRollbackTogether(t *testing.T) {
	o, pool := outboxFixture(t)
	ctx := context.Background()
	err := pgutil.WithTx(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO business VALUES(1)`); err != nil {
			return err
		}
		if err := o.EnqueueTx(ctx, tx, outboxEvent(t)); err != nil {
			return err
		}
		return errors.New("business failure")
	})
	if err == nil {
		t.Fatal("expected rollback")
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM business`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("business survived rollback: %d %v", rows, err)
	}
	b, err := o.Backlog(ctx)
	if err != nil || b.Count != 0 {
		t.Fatalf("event survived rollback: %+v %v", b, err)
	}
	if _, err := pool.Exec(ctx, `DROP TABLE csar_audit_outbox`); err != nil {
		t.Fatal(err)
	}
	err = pgutil.WithTx(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO business VALUES(2)`); err != nil {
			return err
		}
		return o.EnqueueTx(ctx, tx, outboxEvent(t))
	})
	if err == nil {
		t.Fatal("mutation committed without an outbox")
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM business`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("business survived enqueue failure: %d %v", rows, err)
	}
}

type uncertainTransport struct {
	mu   sync.Mutex
	seen []*Event
	fail bool
}

func (t *uncertainTransport) Send(_ context.Context, events []*Event) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range events {
		t.seen = append(t.seen, cloneEvent(e))
	}
	if t.fail {
		return errors.New("receipt lost after acceptance")
	}
	return nil
}
func (*uncertainTransport) Close() error { return nil }

func TestOutboxUncertainReceiptReplaysOriginalIdentity(t *testing.T) {
	o, pool := outboxFixture(t)
	ctx := context.Background()
	e := outboxEvent(t)
	enqueueTest(t, o, e)
	enqueueTest(t, o, e)
	b, err := o.Backlog(ctx)
	if err != nil || b.Count != 1 {
		t.Fatalf("enqueue retry duplicated: %+v %v", b, err)
	}
	transport := &uncertainTransport{fail: true}
	if worked, err := o.DeliverOne(ctx, transport); !worked || err == nil {
		t.Fatal("missing receipt accepted")
	}
	b, err = o.Backlog(ctx)
	if err != nil || b.Count != 1 {
		t.Fatal("uncertainty removed pending event")
	}
	if _, err := pool.Exec(ctx, `UPDATE csar_audit_outbox SET next_attempt=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	transport.fail = false
	if worked, err := o.DeliverOne(ctx, transport); !worked || err != nil {
		t.Fatal(err)
	}
	if len(transport.seen) != 2 || transport.seen[0].ID != e.ID || transport.seen[1].ID != e.ID || !transport.seen[1].CreatedAt.Equal(e.CreatedAt) {
		t.Fatal("relay retry changed event identity")
	}
	b, err = o.Backlog(ctx)
	if err != nil || b.Count != 0 {
		t.Fatal("confirmed delivery retained pending event")
	}
}

func TestOutboxExpiredLeaseCannotDeleteNewClaim(t *testing.T) {
	o, pool := outboxFixture(t)
	ctx := context.Background()
	enqueueTest(t, o, outboxEvent(t))
	stale, err := o.claim(ctx)
	if err != nil || stale == nil {
		t.Fatal(err)
	}
	if next, err := o.claim(ctx); err != nil || next != nil {
		t.Fatal("competing worker acquired live lease")
	}
	if _, err := pool.Exec(ctx, `UPDATE csar_audit_outbox SET lease_until=clock_timestamp()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	current, err := o.claim(ctx)
	if err != nil || current == nil || current.token == stale.token {
		t.Fatal("expired lease not reclaimed")
	}
	if err := o.finish(ctx, stale, true); !errors.Is(err, ErrOutboxLeaseLost) {
		t.Fatalf("stale worker finished another lease: %v", err)
	}
	if err := o.finish(ctx, current, true); err != nil {
		t.Fatal(err)
	}
}

func TestOutboxRejectsIdentityConflictAndSeparatesServices(t *testing.T) {
	o, pool := outboxFixture(t)
	ctx := context.Background()
	e := outboxEvent(t)
	enqueueTest(t, o, e)
	changed := cloneEvent(e)
	changed.Action = "different"
	if err := pgutil.WithTx(ctx, pool, func(tx pgx.Tx) error { return o.EnqueueTx(ctx, tx, changed) }); err == nil {
		t.Fatal("conflicting identity accepted")
	}
	other, err := NewPGOutbox(pool, "another-service")
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := other.claim(ctx); err != nil || claimed != nil {
		t.Fatal("another service claimed foreign audit data")
	}
	var wg sync.WaitGroup
	transport := &uncertainTransport{}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := o.DeliverOne(ctx, transport)
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(transport.seen) != 1 {
		t.Fatal("competing relays delivered more than one live claim")
	}
}

func TestOutboxRetryBound(t *testing.T) {
	for _, n := range []int64{0, 1, 5, 6, 1000} {
		if wait := retrySeconds(n); wait < 1 || wait > 30 {
			t.Fatal("unbounded retry", wait)
		}
	}
	if outboxSendTimeout+outboxDBTimeout >= outboxLease {
		t.Fatal("send and finish exceed lease")
	}
	if _, err := NewPGOutbox(nil, "test"); err == nil {
		t.Fatal("nil pool accepted")
	}
}
