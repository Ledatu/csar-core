package tokenmint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

var (
	// ErrUnknownProfile means the descriptor named a profile the operator has
	// not configured. Never fall back to a default profile: doing so would send
	// a credential to an endpoint nobody chose for it.
	ErrUnknownProfile = errors.New("tokenmint: unknown grant profile")

	// ErrThrottled means a mint was suppressed by the per-credential minimum
	// refresh interval or the per-profile rate limit, and no usable cached
	// token was available to serve instead.
	ErrThrottled = errors.New("tokenmint: mint throttled")

	// ErrBackoff means a previous mint for this credential failed and the
	// backoff window has not elapsed. The wrapped error is the original
	// failure. No network call is made while this is returned.
	ErrBackoff = errors.New("tokenmint: mint in backoff")
)

// Result is a minted bearer token and its two lifetime boundaries.
//
// The two clocks are the point of this type. RefreshAfter is when the token
// becomes eligible for replacement; HardExpiry is when it stops being usable.
// Serving the existing token throughout that window is what makes an upstream
// token-endpoint outage invisible to traffic for most of a token's life.
type Result struct {
	AccessToken  string
	TokenType    string
	RefreshAfter time.Time
	HardExpiry   time.Time
}

// Fresh reports whether the token is new enough that no refresh is due.
func (r *Result) Fresh(now time.Time) bool {
	return !r.RefreshAfter.IsZero() && now.Before(r.RefreshAfter)
}

// Usable reports whether the token can still be served.
func (r *Result) Usable(now time.Time) bool {
	return !r.HardExpiry.IsZero() && now.Before(r.HardExpiry)
}

type mintState struct {
	profileName string

	result    Result
	hasResult bool

	lastMintAt    time.Time
	failCount     int
	lastErr       error
	nextAttemptAt time.Time
}

// Minter executes client_credentials grants with caching, stampede collapsing,
// rate limiting and failure backoff. It is safe for concurrent use.
type Minter struct {
	cfg    *Config
	logger *slog.Logger

	sf singleflight.Group

	mu       sync.Mutex
	state    map[string]*mintState
	limiters map[string]*rate.Limiter
	clients  map[string]*http.Client

	// now is injectable so lifetime and backoff behavior can be tested
	// without sleeping.
	now func() time.Time
}

// New builds a Minter for the given configuration, which must already have
// passed Validate.
func New(cfg *Config, logger *slog.Logger) (*Minter, error) {
	if cfg == nil {
		return nil, fmt.Errorf("tokenmint: config is required")
	}
	if len(cfg.Profiles) == 0 {
		return nil, fmt.Errorf("tokenmint: config has no profiles")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Minter{
		cfg:      cfg,
		logger:   logger,
		state:    make(map[string]*mintState),
		limiters: make(map[string]*rate.Limiter),
		clients:  make(map[string]*http.Client),
		now:      time.Now,
	}, nil
}

// SetClock replaces the time source. Test-only.
func (m *Minter) SetClock(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
}

// Mint returns a usable token for the given credential pair, minting one if
// the cached token is missing or due for refresh.
//
// Concurrent calls for the same credential collapse into a single upstream
// request. The key is the credential pair rather than the caller's token ref,
// so two descriptors pointing at the same client_id mint once between them.
func (m *Minter) Mint(ctx context.Context, profileName, clientID, clientSecret string) (Result, error) {
	profile, ok := m.cfg.Profile(profileName)
	if !ok {
		return Result{}, fmt.Errorf("%w: %q", ErrUnknownProfile, profileName)
	}

	key := credentialKey(profileName, clientID)
	v, err, _ := m.sf.Do(key, func() (any, error) {
		return m.mintOne(ctx, key, profileName, &profile, clientID, clientSecret)
	})
	if err != nil {
		return Result{}, err
	}
	res, ok := v.(Result)
	if !ok {
		return Result{}, fmt.Errorf("tokenmint: unexpected singleflight result type %T", v)
	}
	return res, nil
}

func (m *Minter) mintOne(ctx context.Context, key, profileName string, p *Profile, clientID, clientSecret string) (Result, error) {
	now := m.clock()
	st := m.stateFor(key, profileName)

	m.mu.Lock()
	cached := st.result
	fresh := st.hasResult && cached.Fresh(now)
	fallback := st.hasResult && cached.Usable(now)

	var gateErr error
	switch {
	case fresh:
		// Nothing to do.
	case now.Before(st.nextAttemptAt):
		gateErr = fmt.Errorf("%w until %s: %w", ErrBackoff, st.nextAttemptAt.UTC().Format(time.RFC3339), st.lastErr)
	case !st.lastMintAt.IsZero() && now.Sub(st.lastMintAt) < p.MinRefreshInterval:
		gateErr = fmt.Errorf("%w: min_refresh_interval %s has not elapsed", ErrThrottled, p.MinRefreshInterval)
	}
	m.mu.Unlock()

	if fresh {
		return cached, nil
	}
	if gateErr != nil {
		// A token past its refresh point but before hard expiry is still good.
		// Serving it here is what absorbs an upstream outage.
		if fallback {
			return cached, nil
		}
		return Result{}, gateErr
	}

	if !m.limiterFor(profileName, p).Allow() {
		if fallback {
			return cached, nil
		}
		return Result{}, fmt.Errorf("%w: profile %q exceeded max_mints_per_minute (%v)", ErrThrottled, profileName, p.MaxMintsPerMinute)
	}

	resp, mintErr := doGrant(ctx, m.clientFor(profileName, p), m.cfg, p, clientID, clientSecret)

	m.mu.Lock()
	defer m.mu.Unlock()
	st.lastMintAt = now

	if mintErr != nil {
		st.failCount++
		st.lastErr = mintErr
		backoff := backoffFor(p, mintErr, st.failCount)
		st.nextAttemptAt = now.Add(backoff)

		m.logger.Error("token mint failed",
			"grant_profile", profileName,
			"fail_count", st.failCount,
			"backoff", backoff,
			"serving_cached", fallback,
			"error", mintErr,
		)

		if fallback {
			return cached, nil
		}
		return Result{}, mintErr
	}

	st.failCount = 0
	st.lastErr = nil
	st.nextAttemptAt = time.Time{}
	st.result = resultFrom(now, p, resp)
	st.hasResult = true

	m.logger.Info("token minted",
		"grant_profile", profileName,
		"expires_in", resp.ExpiresIn,
		"refresh_after", st.result.RefreshAfter.UTC().Format(time.RFC3339),
		"hard_expiry", st.result.HardExpiry.UTC().Format(time.RFC3339),
	)

	return st.result, nil
}

// Sweep drops mint state for credentials that have neither been minted nor
// served within their profile's idle TTL, so accounts that stopped receiving
// traffic stop occupying memory. It returns the number of entries dropped.
func (m *Minter) Sweep() int {
	now := m.clock()

	m.mu.Lock()
	defer m.mu.Unlock()

	var dropped int
	for key, st := range m.state {
		p, ok := m.cfg.ProfileRef(st.profileName)
		if !ok {
			delete(m.state, key)
			dropped++
			continue
		}
		if st.lastMintAt.IsZero() || now.Sub(st.lastMintAt) < p.IdleTTL {
			continue
		}
		if st.hasResult && st.result.Usable(now) {
			continue
		}
		delete(m.state, key)
		dropped++
	}
	return dropped
}

// Entries reports how many credential pairs currently hold mint state.
func (m *Minter) Entries() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.state)
}

func (m *Minter) clock() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now()
}

func (m *Minter) stateFor(key, profileName string) *mintState {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.state[key]
	if !ok {
		st = &mintState{profileName: profileName}
		m.state[key] = st
	}
	return st
}

func (m *Minter) limiterFor(profileName string, p *Profile) *rate.Limiter {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.limiters[profileName]; ok {
		return l
	}
	burst := int(p.MaxMintsPerMinute)
	if burst < 1 {
		burst = 1
	}
	l := rate.NewLimiter(rate.Limit(p.MaxMintsPerMinute/60.0), burst)
	m.limiters[profileName] = l
	return l
}

func (m *Minter) clientFor(profileName string, p *Profile) *http.Client {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.clients[profileName]; ok {
		return c
	}
	c := newHTTPClient(m.cfg, p.Timeout)
	m.clients[profileName] = c
	return c
}

func resultFrom(now time.Time, p *Profile, resp grantResponse) Result {
	lifetime := time.Duration(float64(resp.ExpiresIn) * p.ExpiresInHaircut)
	if lifetime <= 0 {
		lifetime = resp.ExpiresIn
	}

	margin := p.RefreshMargin
	if margin >= lifetime {
		margin = lifetime / 2
	}

	hard := now.Add(lifetime)
	return Result{
		AccessToken:  resp.AccessToken,
		TokenType:    resp.TokenType,
		RefreshAfter: hard.Add(-margin),
		HardExpiry:   hard,
	}
}

func backoffFor(p *Profile, err error, failCount int) time.Duration {
	// Bad credentials do not heal on their own. Retrying them quickly wastes
	// quota and risks tripping upstream lockout.
	if errors.Is(err, ErrInvalidClient) {
		return p.AuthErrorBackoff
	}

	var ue *upstreamError
	if errors.As(err, &ue) && ue.retryAfter > 0 {
		return clampDuration(ue.retryAfter, p.ErrorBackoffBase, p.ErrorBackoffMax)
	}

	d := p.ErrorBackoffBase
	for i := 1; i < failCount && d < p.ErrorBackoffMax; i++ {
		d *= 2
	}
	d = clampDuration(d, p.ErrorBackoffBase, p.ErrorBackoffMax)

	// Half jitter: keeps a real floor while still spreading a fleet-wide
	// retry across the window.
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

func clampDuration(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if hi > 0 && d > hi {
		return hi
	}
	return d
}

// credentialKey identifies a credential pair without retaining the client id
// in a map key that may end up in a dump or a log line.
func credentialKey(profileName, clientID string) string {
	sum := sha256.Sum256([]byte(profileName + "\x00" + clientID))
	return hex.EncodeToString(sum[:])
}
