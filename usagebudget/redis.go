// Package usagebudget provides bounded, atomic multi-dimension usage admission.
// Counters have fixed windows anchored at their first accepted use. It is not a
// concurrency lease, byte reservation or substitute for owner compute admission.
package usagebudget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrInvalid = errors.New("usagebudget: invalid admission request")
var ErrUnavailable = errors.New("usagebudget: admission unavailable")

type Exceeded struct {
	Dimension  string
	RetryAfter time.Duration
}

func (e *Exceeded) Error() string { return "usagebudget: usage limit exceeded" }

type Limit struct {
	Dimension, Subject string
	Capacity           int64
}
type Request struct {
	Policy string
	Window time.Duration
	Units  int64
	Limits []Limit
}
type Limiter struct {
	client  redis.UniversalClient
	prefix  string
	timeout time.Duration
}

func New(client redis.UniversalClient, prefix string, timeout time.Duration) (*Limiter, error) {
	if client == nil || len(prefix) > 128 || strings.ContainsAny(prefix, "{}\x00\r\n") || timeout <= 0 || timeout > time.Second {
		return nil, ErrInvalid
	}
	// go-redis otherwise ignores context deadlines during socket IO. Require
	// that capability rather than claiming a timeout the driver does not honor.
	bounded := false
	switch c := client.(type) {
	case *redis.Client:
		bounded = c != nil && c.Options().ContextTimeoutEnabled
	case *redis.ClusterClient:
		bounded = c != nil && c.Options().ContextTimeoutEnabled
	}
	if !bounded {
		return nil, ErrInvalid
	}
	return &Limiter{client: client, prefix: prefix, timeout: timeout}, nil
}

// All dimensions of one policy share a Redis Cluster slot. Raw identities,
// credentials and transport names never appear in keys.
func digest(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}
func (l *Limiter) key(policy string, limit Limit) string {
	return l.prefix + "{usage:" + digest(policy) + "}:" + limit.Dimension + ":" + digest(limit.Subject)
}
func safeName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, b := range []byte(value) {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '_', b == '-', b == '.', b == ':':
		default:
			return false
		}
	}
	return true
}

var admit = redis.NewScript(`
local units = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local blocked = 0
local retry = 0
for i,key in ipairs(KEYS) do
 local raw = redis.call('GET',key)
 local current = tonumber(raw or '0')
 if current == nil or current < 0 or current % 1 ~= 0 then return redis.error_reply('invalid usage counter') end
 local ttl = 0
 if raw then
  ttl = redis.call('PTTL',key)
  if ttl <= 0 then return redis.error_reply('invalid usage expiry') end
 end
 if current + units > tonumber(ARGV[i+2]) and ttl >= retry then blocked = i; retry = ttl end
end
if blocked > 0 then return {blocked,retry} end
for _,key in ipairs(KEYS) do
 local value = redis.call('INCRBY',key,units)
 if value == units then redis.call('PEXPIRE',key,window) end
end
return {0,0}
`)

// Validate permits config compilers to reject invalid policies without Redis IO.
func Validate(request Request) error {
	if !safeName(request.Policy) || request.Window < time.Second || request.Window > 24*time.Hour || request.Units <= 0 || request.Units > 1_000_000_000 || len(request.Limits) == 0 || len(request.Limits) > 8 {
		return ErrInvalid
	}
	seen := make(map[string]bool)
	for i := range request.Limits {
		limit := request.Limits[i]
		if !safeName(limit.Dimension) || limit.Subject == "" || len(limit.Subject) > 512 || limit.Capacity < request.Units || limit.Capacity > 1_000_000_000 || seen[limit.Dimension] {
			return ErrInvalid
		}
		seen[limit.Dimension] = true
	}
	return nil
}

// Take charges every dimension or denies before changing any counters. Redis
// uncertainty fails closed without inferred refunds or application retries.
// Disable driver retries to avoid conservative duplicate charges after a replay.
func (l *Limiter) Take(ctx context.Context, request Request) error {
	if l == nil {
		return ErrInvalid
	}
	if err := Validate(request); err != nil {
		return err
	}
	keys := make([]string, 0, len(request.Limits))
	args := []any{request.Units, request.Window.Milliseconds()}
	for i := range request.Limits {
		limit := request.Limits[i]
		keys = append(keys, l.key(request.Policy, limit))
		args = append(args, limit.Capacity)
	}
	ctx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()
	result, err := admit.Run(ctx, l.client, keys, args...).Slice()
	if err != nil || ctx.Err() != nil || len(result) != 2 {
		return errors.Join(ErrUnavailable, ctx.Err())
	}
	index, indexOK := result[0].(int64)
	retry, retryOK := result[1].(int64)
	if !indexOK || !retryOK || index < 0 || index > int64(len(request.Limits)) || retry < 0 || retry > (24*time.Hour).Milliseconds() {
		return ErrUnavailable
	}
	if index == 0 {
		return nil
	}
	if retry == 0 {
		retry = 1
	}
	return &Exceeded{Dimension: request.Limits[index-1].Dimension, RetryAfter: time.Duration(retry) * time.Millisecond}
}
