# KestrelAcme: plan

Automatic, free HTTPS certificates for ASP.NET Core apps that use Kestrel as the edge server.
One NuGet package, one line of setup:

```csharp
builder.Services.AddKestrelAcme(o =>
{
    o.Domains.Add("example.com");
    o.Email = "ops@example.com";
    o.AcceptTermsOfService = true;
});
```

The app gets a Let's Encrypt certificate on first start, renews it in the background and switches to the new
certificate without a restart.

## Why

- [dotnet/aspnetcore#4712](https://github.com/dotnet/aspnetcore/issues/4712) (ACME support in Kestrel) has been
  open since 2016 with ~200 👍. Microsoft has not built it.
- The library everyone used, LettuceEncrypt, was archived in 2025. Its last release targets .NET 6.
- Certificate lifetimes are shrinking: 200 days in 2026, 47 days by 2029 (CA/Browser Forum), and Let's Encrypt
  offers 6-day certificates. Renewing by hand stops being an option.

## Scope of 0.1

| In | Out (later) |
|---|---|
| ACME client (RFC 8555), written from scratch, no third-party dependencies | DNS-01 and wildcard certificates (0.2, with a provider interface) |
| HTTP-01 challenge (port 80) | Shared storage and locking for several instances behind a load balancer (0.2) |
| TLS-ALPN-01 challenge (RFC 8737, port 443 only) | Azure Key Vault and Redis stores (0.3) |
| ACME Renewal Information (ARI, RFC 9773) with fallback to "renew at 1/3 lifetime left" | IIS, HTTP.sys |
| Certificate profiles (`shortlived` etc.) | |
| External account binding (ZeroSSL, Google Trust Services) | |
| Hot swap of the certificate with the full chain sent to clients | |
| File-system store, pluggable `ICertificateStore` | |
| Logs, metrics (`System.Diagnostics.Metrics`), health check | |

## Design

```
            ┌────────────────────── AddKestrelAcme() ──────────────────────┐
            │                                                              │
 Kestrel ── ClientHelloMiddleware ── HttpsConnectionMiddleware ── app      │
            │ peeks SNI + ALPN          │ OnAuthenticate picks:            │
            │ without consuming bytes   │  - challenge cert (acme-tls/1)   │
            │                           │  - CertificateSelector (SNI)     │
            │                                                              │
            │  Http01ChallengeMiddleware (IStartupFilter, runs first)      │
            │                                                              │
            │  AcmeRenewalService (BackgroundService)                      │
            │    waits for ApplicationStarted → load from store            │
            │    → issue/renew via AcmeCertificateIssuer → store → swap   │
            │                                                              │
            │  AcmeClient: directory, nonces, JWS (ES256), orders, ARI    │
            └──────────────────────────────────────────────────────────────┘
```

Decisions:

1. **Own ACME client.** The protocol is small (JWS + about 8 endpoints). Owning it removes a dependency that could
   go stale like LettuceEncrypt's did, and keeps the package trimming and AOT friendly (source-generated JSON).
2. **Hooking into Kestrel without asking the user to touch endpoints.** An `IConfigureOptions<KestrelServerOptions>`
   adds defaults to every endpoint:
   - a connection middleware that reads the TLS ClientHello from the pipe *without consuming it* and records SNI
     and ALPN;
   - HTTPS defaults whose `OnAuthenticate` sets the certificate context (leaf + intermediates, so clients get the
     full chain) or, for a TLS-ALPN-01 validation, the challenge certificate and `acme-tls/1`.
   .NET's `SslClientHelloInfo` does not expose ALPN, which is why the ClientHello is parsed by hand.
3. **Never fail a handshake because of us.** Until a real certificate exists, a self-signed fallback is served.
   If the ClientHello can't be parsed, the connection continues untouched.
4. **Time is injected** (`TimeProvider`), so the renewal schedule is unit-tested without waiting.
5. **Failures back off** exponentially (1 min → 6 h), and `Retry-After` / rate-limit responses are respected.
   An expired certificate keeps being served rather than nothing.
6. **Secrets at rest:** account key and certificates are written with owner-only permissions on Unix.
   The store is an interface, so users with stricter needs can plug in Key Vault etc.

## Testing

- **Unit:** JWS signatures verify, JWK thumbprint, ClientHello parser (fed with real ClientHellos produced by
  `SslStream`), TLS-ALPN challenge certificate (RFC 8737 extension), ARI certificate ID, renewal schedule,
  options validation.
- **Integration against Pebble**, Let's Encrypt's own test server (pinned v2.10.1). Pebble rejects 5% of nonces on
  purpose, so retry logic is exercised every run. The tests start a real Kestrel app and check that:
  - a certificate is issued through HTTP-01, and through TLS-ALPN-01 alone;
  - a TLS client connecting with SNI gets that certificate and its chain;
  - a renewal replaces the certificate without a restart.
  The tests are skipped (with a message) when Pebble isn't installed. `eng/pebble.sh` builds it.
- **CI:** Linux, Windows, macOS unit tests; Pebble integration on Linux; pack.

## Milestones

| # | Deliverable |
|---|---|
| 1 | Repo skeleton, options + validation, ACME client with JWS and nonce handling |
| 2 | Certificate factory (CSR, chain import, challenge and fallback certs), file store |
| 3 | Kestrel integration: ClientHello middleware, selector, HTTP-01 middleware |
| 4 | Issuer + renewal service + ARI, metrics, health check |
| 5 | Pebble integration tests, sample app, CI |
| 6 | README, docs, 0.1.0 on NuGet, LinkedIn post |

## Risks

- **Kestrel internals change between versions.** Only public APIs are used (`ListenOptions.Use`, `OnAuthenticate`);
  CI covers .NET 8 and 10.
- **Rate limits during development.** Defaults point at production, but docs and the sample use staging, and the
  integration tests never touch Let's Encrypt.
- **Several instances renewing at once.** Documented as a 0.1 limitation, fixed in 0.2 with a lock interface.
