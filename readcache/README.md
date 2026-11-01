# Bounded local reuse

`Group[T]` is the shared in-flight registry used by CSAR's HTTP response cache
and `Scope`. `Scope` adds short-lived byte memoization for one request or job.
Neither is distributed singleflight, a Redis client, an authorization layer or
a freshness policy.

- Positive limits are mandatory: active keys, followers per key, key size,
  retained entries (including reservations), retained bytes, value size and age.
- `Begin` admits one leader. Followers release their slots on timeout/cancellation;
  releasing a follower never cancels the leader or starts a second load.
- `Finish` accepts only the current ticket and is idempotent. `Do` completes a
  panicking leader's ticket with `ErrAborted` and propagates the panic to its caller.
  Low-level users must defer both `release()` and a fallback `Finish`.
- A leader uses its initiating caller's context. Its error is shared; followers
  do not transparently retry. No detached background work is created by this API.
- `Scope.Resolve` retains successes only, copies mutable bytes in and out, and
  rejects oversized values or full storage. Loaders must bound their own working
  allocations and honor context cancellation. Retained-byte limits do not bound
  transient provider allocations, response copies or other service memory.
- `defer scope.Close()` is required. The earlier parent deadline or MaxAge ends
  reads and cancels active cooperative loads. Close releases retained entries.
  Expiry alone does not promise immediate memory reclamation from a live reference.
- Limits are per instance. They do not provide seller-wide admission, source
  rate limits, cross-process ownership, eviction, durable storage or fencing.

Construct semantic keys in the owning read model. Include all data-access and
calculation distinctions, then authorize every use before lookup. Do not reuse a
scope across permission partitions. HTTP key policy remains in CSAR.

The Redis/lease stage must build on this primitive without claiming that a local
flight prevents duplicate SQL across replicas. A lease token alone does not make
publication safe; publication needs an ownership-checked commit protocol.
