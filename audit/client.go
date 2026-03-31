package audit

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"
)

const (
	defaultClientBufferSize   = 1000
	defaultClientFlushTimeout = 100 * time.Millisecond
	defaultClientWorkers      = 2
	defaultClientMaxBatch     = 100
	defaultClientSendTimeout  = 30 * time.Second
	batchOutChanMultiplier    = 4
)

// Transport delivers audit events to a remote ingest (gRPC, HTTP, tests, etc.).
type Transport interface {
	Send(ctx context.Context, events []*Event) error
	Close() error
}

// ClientConfig configures async audit recording.
type ClientConfig struct {
	Transport Transport
	// BufferSize is the capacity of the in-memory queue. Zero defaults to 1000.
	BufferSize int
	// FlushTimeout debounces batch sends. Zero defaults to 100ms.
	FlushTimeout time.Duration
	// Workers is the number of parallel Send calls. Zero defaults to 2.
	Workers int
	// FallbackToLog enables slog fallback when the queue is full or Send fails.
	// Nil defaults to true; use Bool(false) to disable.
	FallbackToLog *bool
}

// Bool returns a pointer to b for use in ClientConfig (e.g. FallbackToLog: audit.Bool(false)).
func Bool(b bool) *bool {
	return &b
}

// Client batches and sends audit events without blocking callers.
type Client struct {
	cfg         ClientConfig
	fallbackLog bool
	log         *slog.Logger
	events      chan *Event
	batches     chan []*Event

	mu     sync.Mutex
	closed bool

	wg sync.WaitGroup
}

// NewClient starts background workers that drain the internal queue into Transport.
func NewClient(cfg ClientConfig, logger *slog.Logger) (*Client, error) {
	if cfg.Transport == nil {
		return nil, errors.New("audit: ClientConfig.Transport is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = defaultClientBufferSize
	}
	if cfg.FlushTimeout <= 0 {
		cfg.FlushTimeout = defaultClientFlushTimeout
	}
	if cfg.Workers <= 0 {
		cfg.Workers = defaultClientWorkers
	}

	fb := true
	if cfg.FallbackToLog != nil {
		fb = *cfg.FallbackToLog
	}

	outCap := cfg.Workers * batchOutChanMultiplier
	if outCap < 4 {
		outCap = 4
	}

	c := &Client{
		cfg:         cfg,
		fallbackLog: fb,
		log:         logger,
		events:      make(chan *Event, cfg.BufferSize),
		batches:     make(chan []*Event, outCap),
	}

	c.wg.Add(1 + cfg.Workers)
	go c.dispatchLoop()
	for range cfg.Workers {
		go c.workerLoop()
	}

	return c, nil
}

// Record enqueues an event copy and returns immediately. It never returns an error.
// If the buffer is full or the client is closed, the event is dropped according to FallbackToLog.
func (c *Client) Record(_ context.Context, event *Event) {
	if event == nil {
		return
	}

	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		c.logFallback(cloneEvent(event), "client_closed")
		return
	}

	select {
	case c.events <- cloneEvent(event):
	default:
		c.logFallback(cloneEvent(event), "buffer_full")
	}
}

// RecordSync sends a single event immediately through the transport.
func (c *Client) RecordSync(ctx context.Context, event *Event) error {
	if event == nil {
		return nil
	}
	if c.cfg.Transport == nil {
		return errors.New("audit: transport is nil")
	}
	return c.cfg.Transport.Send(ctx, []*Event{cloneEvent(event)})
}

// Close flushes queued events, stops workers, and closes the transport.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return c.cfg.Transport.Close()
	}
	c.closed = true
	c.mu.Unlock()

	close(c.events)
	c.wg.Wait()

	return c.cfg.Transport.Close()
}

func (c *Client) dispatchLoop() {
	defer c.wg.Done()
	defer close(c.batches)

	var batch []*Event
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}

	flush := func() {
		if len(batch) == 0 {
			return
		}
		out := batch
		batch = nil
		select {
		case c.batches <- out:
		default:
			if c.fallbackLog {
				for _, e := range out {
					c.logFallback(e, "batch_channel_full")
				}
			}
		}
	}

	for {
		if len(batch) == 0 {
			e, ok := <-c.events
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			timer.Reset(c.cfg.FlushTimeout)
			continue
		}

		select {
		case e, ok := <-c.events:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= defaultClientMaxBatch {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				flush()
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(c.cfg.FlushTimeout)
			}
		case <-timer.C:
			flush()
		}
	}
}

func (c *Client) workerLoop() {
	defer c.wg.Done()
	for batch := range c.batches {
		ctx, cancel := context.WithTimeout(context.Background(), defaultClientSendTimeout)
		err := c.cfg.Transport.Send(ctx, batch)
		cancel()
		if err != nil && c.fallbackLog {
			for _, e := range batch {
				c.logFallbackErr(e, err)
			}
		}
	}
}

func (c *Client) logFallback(event *Event, reason string) {
	if !c.fallbackLog {
		return
	}
	payload, err := json.Marshal(event)
	if err != nil {
		c.log.Warn("audit event not delivered", "reason", reason, "marshal_error", err)
		return
	}
	c.log.Warn("audit event not delivered", "reason", reason, "event", json.RawMessage(payload))
}

func (c *Client) logFallbackErr(event *Event, sendErr error) {
	if !c.fallbackLog {
		return
	}
	payload, err := json.Marshal(event)
	if err != nil {
		c.log.Warn("audit transport error", "error", sendErr, "marshal_error", err)
		return
	}
	c.log.Warn("audit transport error", "error", sendErr, "event", json.RawMessage(payload))
}

func cloneEvent(e *Event) *Event {
	if e == nil {
		return nil
	}
	cp := *e
	return &cp
}
