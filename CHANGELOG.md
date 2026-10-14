# Changelog

## [Unreleased]

Fixes from a review of the multi-instance support, all with tests:

- Challenge answers are published once per order and read at most once a second by the other instances, instead of
  one store read per request with a limit of 4: under Let's Encrypt's multi-location validation, or requests for
  made-up tokens, answers could be refused and validation fail.
- A Kubernetes lease renewal that hangs is cut off at the 40 s deadline, so the holder still gives up before another
  replica can take over.
- The lock is kept until the issued certificate is stored, so another instance doesn't order again.
- An error reading the store backs off instead of counting as "no certificate" and ordering.
- With a custom `IAcmeStore` and no `IAcmeLock`, nothing is written to or read from the store for challenges, and a
  log line says instances won't coordinate.
- `KubernetesAcmeOptions.Name` is validated at startup.
- `IAcmeLockHandle` (public) lets a custom lock signal that it was lost.
- The Kubernetes API server's intermediate certificates are used to validate it.
- HTTP-01 answers are logged at Debug, as TLS-ALPN-01 answers are.

## [0.2.0]

- Several instances behind a load balancer share one certificate. One orders it under a lock (`IAcmeLock`), held
  until the order succeeds so the others don't multiply retries; the others pick it up from the store without a
  restart. Challenge answers are shared through the store, so any instance can answer the CA.
- The default lock is a file lock next to the certificate: replicas sharing `StoragePath` on a volume coordinate
  with no configuration.
- `AddKestrelAcmeKubernetes()`: storage in Secrets and a Lease for the lock, calling the API server directly
  (no client library).
- `IAcmeStore.DeleteAsync`, with a default implementation, so existing stores keep compiling.

## [0.1.0]

First release.

- Certificates from any ACME CA (RFC 8555), Let's Encrypt by default.
- HTTP-01, TLS-ALPN-01 and DNS-01 challenges, chosen per domain, with automatic fallback.
- Wildcard certificates through DNS-01 and a pluggable `IDnsChallengeProvider`.
- Renewal driven by ACME Renewal Information (RFC 9773), with `replaces`; otherwise at one third of the lifetime.
- Certificate swap without restart, full chain sent to clients, self-signed placeholder until the first issuance.
- Certificate profiles, external account binding, ECDSA and RSA keys.
- Pluggable storage (`IAcmeStore`), file-system store by default.
- Logs, metrics and traces (`KestrelAcme`), health check.
- .NET 8 and .NET 10. Trimming and Native AOT compatible.
