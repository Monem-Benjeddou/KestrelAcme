# Changelog

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
