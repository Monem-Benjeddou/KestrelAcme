# KestrelAcme

[![CI](https://github.com/Monem-Benjeddou/KestrelAcme/actions/workflows/ci.yml/badge.svg)](https://github.com/Monem-Benjeddou/KestrelAcme/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/KestrelAcme.svg)](https://www.nuget.org/packages/KestrelAcme)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Free, automatic HTTPS for ASP.NET Core, on Windows, Linux and macOS. KestrelAcme gets a certificate from Let's Encrypt (or any ACME CA)
when your app starts, renews it in the background and swaps it in without a restart.

```csharp
builder.Services.AddKestrelAcme(o =>
{
    o.Domains.Add("example.com");
    o.Email = "ops@example.com";
    o.AcceptTermsOfService = true;
});
```

That's the whole setup. No certbot, no cron job, no reverse proxy.

## Why

ACME support in Kestrel is one of the oldest open requests in ASP.NET Core
([dotnet/aspnetcore#4712](https://github.com/dotnet/aspnetcore/issues/4712), open since 2016).
The library most people used, LettuceEncrypt, was archived in 2025. Meanwhile certificate lifetimes keep
shrinking (47 days by 2029, 6-day certificates already available), so renewing by hand isn't an option.

## Features

- **Both challenge types that work without DNS access:** TLS-ALPN-01 (port 443 only) and HTTP-01 (port 80).
  It tries TLS-ALPN-01 first and falls back to HTTP-01, and skips a type Kestrel isn't listening for.
- **Renews when the CA says so** (ACME Renewal Information, RFC 9773), with the `replaces` field so renewals
  are exempt from Let's Encrypt rate limits. Without ARI: when a third of the lifetime is left.
- **Zero-downtime swap.** New handshakes get the new certificate immediately. The full chain is sent.
- **Starts fast.** The stored certificate is loaded before Kestrel accepts its first connection.
- **Never breaks a handshake.** A self-signed placeholder is served until the first certificate arrives.
- **Plays well with others.** Endpoints that configure their own certificate are left alone. HTTP-01 answers
  run before your middleware, so `UseHttpsRedirection` or authentication can't block them.
- **Production details:** remembers which challenge type works so failed validations don't eat rate limits,
  exponential backoff honouring `Retry-After`, nonce retry, internationalized domain names, profiles
  (`o.Profile = "shortlived"`), external account binding (ZeroSSL, Google Trust Services), RSA or ECDSA keys.
- **Observable:** structured logs, OpenTelemetry metrics and traces (`KestrelAcme`), and a health check.
- **No dependencies** beyond ASP.NET Core. Trimming and Native AOT compatible. .NET 8 and .NET 10.

## Getting started

```
dotnet add package KestrelAcme
```

Requirements:

1. Kestrel is the edge server: no proxy terminating TLS in front of it.
2. The domain's DNS points at the machine.
3. Kestrel listens on **443** (and on **80** if you want HTTP-01).

```csharp
using KestrelAcme;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls("http://*:80", "https://*:443");
builder.Services.AddKestrelAcme(builder.Configuration.GetSection("Acme"));
builder.Services.AddHealthChecks().AddKestrelAcme();

var app = builder.Build();
app.UseHttpsRedirection();
app.MapGet("/", () => "Hello over HTTPS!");
app.MapHealthChecks("/healthz");
app.Run();
```

```json
{
  "Acme": {
    "Domains": [ "example.com", "www.example.com" ],
    "Email": "ops@example.com",
    "AcceptTermsOfService": true,
    "DirectoryUri": "https://acme-staging-v02.api.letsencrypt.org/directory"
  }
}
```

Start with Let's Encrypt **staging** (as above) and remove `DirectoryUri` once it works: staging certificates
aren't trusted by browsers, but its rate limits are much higher.

> Using `WebApplication.CreateSlimBuilder` (Native AOT)? Add `builder.WebHost.UseKestrelHttpsConfiguration();`
> so Kestrel accepts `https://` addresses.

## Options

| Option | Default | |
|---|---|---|
| `Domains` | (required) | Names on the certificate. The first is the subject. |
| `AcceptTermsOfService` | `false` | Must be `true`. |
| `Email` | none | For expiry notices from the CA. |
| `DirectoryUri` | Let's Encrypt production | `AcmeDirectories.LetsEncryptStaging`, or another CA. |
| `Challenges` | `Http01 \| TlsAlpn01` | Which challenge types may be used. |
| `KeyAlgorithm` | `EcdsaP256` | `EcdsaP384`, `Rsa2048`, `Rsa4096`. |
| `Profile` | CA default | e.g. `"shortlived"` on Let's Encrypt. |
| `RenewBefore` | ARI, else 1/3 of lifetime | Fixed margin, e.g. `TimeSpan.FromDays(30)`. |
| `StoragePath` | `<LocalApplicationData>/KestrelAcme` | Where the account key and certificates live. |
| `ExternalAccountBinding` | none | `new("key-id", "hmac-key")` for CAs that need it. |
| `IssuanceTimeout` | 5 minutes | Per order. |

### Storage

The account key and certificates are written to `StoragePath`, readable only by the current user: mode 0600/0700
on Linux and macOS, and on Windows an ACL limited to the current user, SYSTEM and Administrators.
**In a container, mount that folder as a volume**, or every restart orders a new certificate and you'll hit rate
limits. Accounts without a home folder (systemd `DynamicUser`, containers without `HOME`) must set `StoragePath`.

To keep them elsewhere (Key Vault, a database, blob storage), implement `IAcmeStore`: two methods, read and write
bytes by key. Register it before `AddKestrelAcme`:

```csharp
builder.Services.AddSingleton<IAcmeStore, MyKeyVaultStore>();
```

### Proxies and custom HTTP settings

The CA is called through a named `HttpClient`:

```csharp
builder.Services.AddHttpClient(AcmeServiceCollectionExtensions.HttpClientName)
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { Proxy = new WebProxy("http://proxy:3128") });
```

### Monitoring

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m.AddMeter("KestrelAcme"))
    .WithTracing(t => t.AddSource("KestrelAcme"));
```

| Metric | |
|---|---|
| `kestrelacme.certificate.time_to_expiry` | Seconds until the served certificate expires. Alert on this. |
| `kestrelacme.issuances` | Orders, tagged `result=success\|failure`. |
| `kestrelacme.issuance.duration` | Seconds per order. |

The health check reports *Degraded* while the placeholder is served or less than 7 days are left, and
*Unhealthy* once the certificate has expired.

## Limitations (0.1)

- **One instance per domain.** Several instances behind a load balancer would each order their own
  certificate, and a challenge may hit the wrong instance. Shared storage and locking are planned for 0.2.
- **No wildcard certificates** yet: they need the DNS-01 challenge (planned, with a provider interface).
- **No HTTP/3 yet.** Kestrel refuses the TLS hook KestrelAcme uses on HTTP/3 endpoints: an endpoint with
  `Protocols = Http1AndHttp2AndHttp3` fails to start with *"The OnAuthenticate callback is not supported with
  HTTP/3"*. HTTP/1.1 and HTTP/2 (Kestrel's default) are fine. HTTP/3 support is planned for 0.2.
- Kestrel only: not IIS or HTTP.sys.
- On Linux, ports below 1024 need root or `CAP_NET_BIND_SERVICE`
  (`sudo setcap 'cap_net_bind_service=+ep' /path/to/app`).

## How it works

```
TCP ─▶ ClientHello peek ─▶ TLS (OnAuthenticate) ─▶ HTTP-01 middleware ─▶ your app
       reads SNI + ALPN    picks the challenge or
       without consuming   the current certificate
```

- A Kestrel connection middleware reads the TLS ClientHello without consuming it. .NET's `SslClientHelloInfo`
  doesn't expose the client's ALPN list, which TLS-ALPN-01 needs.
- `OnAuthenticate` hands `SslStream` a certificate context (leaf + intermediates) or, for an `acme-tls/1`
  validation, the challenge certificate.
- A background service orders, renews and stores certificates. The ACME client (RFC 8555, JWS/ES256) is written
  from scratch in a few hundred lines, so there is no dependency to go stale.

## Development

```
eng/pebble.sh        # or eng/pebble.ps1 on Windows; needs Go. Builds Let's Encrypt's test CA.
dotnet test
```

The integration tests start Pebble and a real Kestrel app, then check issuance through each challenge type,
the chain sent to clients, reuse after restart, and renewal triggered by ARI. Pebble rejects 5% of nonces on
purpose, so the retry path runs every time. Without Pebble those tests are skipped. CI runs everything on
Linux, Windows and macOS, on .NET 8 and 10.

## License

[MIT](LICENSE)
