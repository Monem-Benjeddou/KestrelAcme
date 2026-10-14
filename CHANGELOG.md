# Changelog

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
