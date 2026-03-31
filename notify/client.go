package notify

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

// ClientConfig configures async notification delivery.
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

// Bool returns a pointer to b for use in ClientConfig.
func Bool(b bool) *bool {
	return &b
}

// Client batches and sends notifications without blocking callers.
type Client struct {
	cfg           ClientConfig
	fallbackLog   bool
	log           *slog.Logger
	notifications chan *Notification
	batches       chan []*Notification

	mu     sync.Mutex
	closed bool

	wg sync.WaitGroup
}

// NewClient starts background workers that drain the internal queue into Transport.
func NewClient(cfg ClientConfig, logger *slog.Logger) (*Client, error) {
	if cfg.Transport == nil {
		return nil, errors.New("notify: ClientConfig.Transport is required")
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
		cfg:           cfg,
		fallbackLog:   fb,
		log:           logger,
		notifications: make(chan *Notification, cfg.BufferSize),
		batches:       make(chan []*Notification, outCap),
	}

	c.wg.Add(1 + cfg.Workers)
	go c.dispatchLoop()
	for range cfg.Workers {
		go c.workerLoop()
	}

	return c, nil
}

// Record enqueues a notification copy and returns immediately.
func (c *Client) Record(_ context.Context, notification *Notification) {
	if notification == nil {
		return
	}

	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		c.logFallback(cloneNotification(notification), "client_closed")
		return
	}

	select {
	case c.notifications <- cloneNotification(notification):
	default:
		c.logFallback(cloneNotification(notification), "buffer_full")
	}
}

// RecordSync sends a single notification immediately through the transport.
func (c *Client) RecordSync(ctx context.Context, notification *Notification) error {
	if notification == nil {
		return nil
	}
	if c.cfg.Transport == nil {
		return errors.New("notify: transport is nil")
	}
	return c.cfg.Transport.Send(ctx, []*Notification{cloneNotification(notification)})
}

// Close flushes queued notifications, stops workers, and closes the transport.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return c.cfg.Transport.Close()
	}
	c.closed = true
	c.mu.Unlock()

	close(c.notifications)
	c.wg.Wait()

	return c.cfg.Transport.Close()
}

func (c *Client) dispatchLoop() {
	defer c.wg.Done()
	defer close(c.batches)

	var batch []*Notification
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
				for _, n := range out {
					c.logFallback(n, "batch_channel_full")
				}
			}
		}
	}

	for {
		if len(batch) == 0 {
			n, ok := <-c.notifications
			if !ok {
				flush()
				return
			}
			batch = append(batch, n)
			timer.Reset(c.cfg.FlushTimeout)
			continue
		}

		select {
		case n, ok := <-c.notifications:
			if !ok {
				flush()
				return
			}
			batch = append(batch, n)
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
			for _, n := range batch {
				c.logFallbackErr(n, err)
			}
		}
	}
}

func (c *Client) logFallback(notification *Notification, reason string) {
	if !c.fallbackLog {
		return
	}
	payload, err := json.Marshal(notification)
	if err != nil {
		c.log.Warn("notification not delivered", "reason", reason, "marshal_error", err)
		return
	}
	c.log.Warn("notification not delivered", "reason", reason, "notification", json.RawMessage(payload))
}

func (c *Client) logFallbackErr(notification *Notification, sendErr error) {
	if !c.fallbackLog {
		return
	}
	payload, err := json.Marshal(notification)
	if err != nil {
		c.log.Warn("notify transport error", "error", sendErr, "marshal_error", err)
		return
	}
	c.log.Warn("notify transport error", "error", sendErr, "notification", json.RawMessage(payload))
}
