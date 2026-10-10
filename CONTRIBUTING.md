# Contributing to KestrelAcme

Thanks for helping! Bug reports, fixes and new certificate authorities tested are all welcome.

## Reporting a bug

Open an issue with:

- the KestrelAcme version, your .NET version and OS;
- your `AcmeOptions` (without secrets) and how Kestrel's endpoints are configured;
- the `KestrelAcme` log lines, at `Debug` level if you can (`"Logging:LogLevel:KestrelAcme": "Debug"`).

## Building and testing

You need the .NET 8 and .NET 10 SDKs, and Go for the integration tests.

```bash
eng/pebble.sh      # Windows: eng/pebble.ps1. Builds Pebble, Let's Encrypt's test CA, into .pebble/
dotnet test        # unit tests, then the Pebble integration tests
```

Never test against Let's Encrypt production: use Pebble, or Let's Encrypt staging for a manual check.

## How the code is organized

| Folder | Responsibility |
|---|---|
| `Protocol/` | The ACME client (RFC 8555): JWS signing, nonces, orders, ARI. No ASP.NET Core types here. |
| `Certificates/` | CSRs, chain import, the TLS-ALPN-01 and placeholder certificates, the ARI certificate ID. |
| `Hosting/` | Kestrel integration (ClientHello peek, `OnAuthenticate`), the HTTP-01 middleware, the issuer and the renewal service. |
| `Storage/` | `IAcmeStore` and the file-system implementation. |
| `Diagnostics/` | Logs, metrics, traces, the health check. |

Time comes from `TimeProvider`, and scheduling decisions live in `RenewalPlanner` as pure functions. Keep it
that way, so they stay testable without waiting.

## Pull requests

- Keep them focused: one fix or feature per PR.
- Match the existing style. The build treats warnings as errors, including trimming/AOT warnings.
- Add or update tests, and make sure `dotnet test` passes with Pebble running the integration tests.
