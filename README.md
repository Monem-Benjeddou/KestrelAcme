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

That's the whole setup. No certbot, no cron job, no reverse proxy. Wildcards work too, through DNS-01.

## Why

ACME support in Kestrel is one of the oldest open requests in ASP.NET Core
([dotnet/aspnetcore#4712](https://github.com/dotnet/aspnetcore/issues/4712), open since 2016).
The library most people used, LettuceEncrypt, was archived in 2025. Meanwhile certificate lifetimes keep
shrinking (47 days by 2029, 6-day certificates already available), so renewing by hand isn't an option.

## Features

- **All three challenge types:** TLS-ALPN-01 (port 443 only), HTTP-01 (port 80) and DNS-01 (through your DNS
  host's API). It picks per domain, falls back from one to the next, and skips a type it can't answer.
- **Wildcard certificates** (`*.example.com`) via DNS-01, in the same certificate as `example.com`.
- **Renews when the CA says so** (ACME Renewal Information, RFC 9773), with the `replaces` field so renewals
  are exempt from Let's Encrypt rate limits. Without ARI: when a third of the lifetime is left.
- **Zero-downtime swap.** New handshakes get the new certificate immediately. The full chain is sent.
- **Starts fast.** The stored certificate is loaded before Kestrel accepts its first connection.
- **Never breaks a handshake.** A self-signed placeholder is served until the first certificate arrives.
- **Several instances, one certificate.** Replicas behind a load balancer take turns through a lock: one orders,
  the others pick up the certificate it stores, and any of them answers the CA's challenges. Works on a shared
  volume with no setup, and in Kubernetes through Secrets and a Lease, without a client library.
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
| `Challenges` | `All` | Which challenge types may be used. DNS-01 also needs an `IDnsChallengeProvider`. |
| `DnsPropagationDelay` | 30 seconds | Wait between creating TXT records and asking the CA to check them. |
| `KeyAlgorithm` | `EcdsaP256` | `EcdsaP384`, `Rsa2048`, `Rsa4096`. |
| `Profile` | CA default | e.g. `"shortlived"` on Let's Encrypt. |
| `RenewBefore` | ARI, else 1/3 of lifetime | Fixed margin, e.g. `TimeSpan.FromDays(30)`. |
| `StoragePath` | `<LocalApplicationData>/KestrelAcme` | Where the account key and certificates live. |
| `ExternalAccountBinding` | none | `new("key-id", "hmac-key")` for CAs that need it. |
| `IssuanceTimeout` | 5 minutes | Per order. |

### Wildcards and DNS-01

DNS-01 proves control by publishing a TXT record, so it works for wildcard names and for servers that aren't
reachable from the internet. Implement `IDnsChallengeProvider` (two methods) for your DNS host and register it:

```csharp
builder.Services.AddSingleton<IDnsChallengeProvider, CloudflareDns>();
builder.Services.AddKestrelAcme(o =>
{
    o.Domains.Add("example.com");
    o.Domains.Add("*.example.com");   // DNS-01; example.com itself can still use TLS-ALPN-01
    o.AcceptTermsOfService = true;
});
```

Here is a provider for Cloudflare, as an example (an API token with *Zone → DNS → Edit*):

```csharp
sealed class CloudflareDns(IHttpClientFactory http, IConfiguration config) : IDnsChallengeProvider
{
    private HttpClient Client()
    {
        var client = http.CreateClient();
        client.BaseAddress = new($"https://api.cloudflare.com/client/v4/zones/{config["Cloudflare:ZoneId"]}/");
        client.DefaultRequestHeaders.Authorization = new("Bearer", config["Cloudflare:Token"]);
        return client;
    }

    public async Task AddTxtRecordAsync(string name, string value, CancellationToken ct) =>
        (await Client().PostAsJsonAsync("dns_records", new { type = "TXT", name, content = value, ttl = 60 }, ct))
            .EnsureSuccessStatusCode();

    public async Task RemoveTxtRecordAsync(string name, string value, CancellationToken ct)
    {
        var client = Client();
        var found = await client.GetFromJsonAsync<JsonElement>(
            $"dns_records?type=TXT&name={Uri.EscapeDataString(name)}&content={Uri.EscapeDataString(value)}", ct);
        foreach (var record in found.GetProperty("result").EnumerateArray())
            (await client.DeleteAsync($"dns_records/{record.GetProperty("id").GetString()}", ct)).EnsureSuccessStatusCode();
    }
}
```

After creating the records, KestrelAcme waits `DnsPropagationDelay` (30 s by default) before asking the CA to
check them.

### Storage

The account key and certificates are written to `StoragePath`, readable only by the current user: mode 0600/0700
on Linux and macOS, and on Windows an ACL limited to the current user, SYSTEM and Administrators.
**In a container, mount that folder as a volume**, or every restart orders a new certificate and you'll hit rate
limits. Accounts without a home folder (systemd `DynamicUser`, containers without `HOME`) must set `StoragePath`.

To keep them elsewhere (Key Vault, a database, blob storage), implement `IAcmeStore`: two methods, read and write
bytes by key, and optionally `DeleteAsync` to clean up challenge answers. Register it before `AddKestrelAcme`:

```csharp
builder.Services.AddSingleton<IAcmeStore, MyKeyVaultStore>();
```

### Several instances

Replicas of an app behind a load balancer share one certificate. When it's due, one replica takes a lock and
orders it; the others wait, then load it from the store, without a restart. The lock is held until the order
succeeds, retries included, so the replicas don't multiply failed attempts against the CA's rate limits. Challenge
answers go through the store too, so whichever replica the CA reaches can answer.

**On a shared volume** (NFSv4, SMB/Azure Files, EFS), point every replica's `StoragePath` at it. Nothing else to
configure: the lock is a file lock, released at once if the replica's process crashes, and by the file server
(about 90 s on NFSv4) if its whole node is lost. Don't set `DOTNET_SYSTEM_IO_DISABLEFILELOCKING`, which turns
file locks off.

**In Kubernetes**, without a shared volume, keep the state in the API server:

```csharp
builder.Services.AddKestrelAcme(builder.Configuration.GetSection("Acme"));
builder.Services.AddKestrelAcmeKubernetes(); // Secrets for storage, a Lease for the lock
```

Each value is a Secret of its own, named `kestrelacme-store-…`, and the lock is a Lease, renewed every 20 s while
held. A replica that can't renew it for 40 s (cut off from the API server) abandons its order; the others take
over only after 60 s without a renewal, so two replicas never order at once. It calls the API server directly with the pod's service
account, which needs this Role (and a RoleBinding to it):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: kestrelacme }
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, create, update, delete]
  - apiGroups: [coordination.k8s.io]
    resources: [leases]
    verbs: [get, create, update]
```

Set `o.Name` to keep two apps in one namespace apart. TLS still has to reach the pods: expose them through a
`LoadBalancer` Service or a TCP (passthrough) ingress, not one that terminates TLS.

**With a custom `IAcmeStore`**, also register an `IAcmeLock` backed by the same system (a database lock, a blob
lease); without one, replicas don't coordinate.

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

## Limitations

- **No HTTP/3 yet.** Kestrel refuses the TLS hook KestrelAcme uses on HTTP/3 endpoints: an endpoint with
  `Protocols = Http1AndHttp2AndHttp3` fails to start with *"The OnAuthenticate callback is not supported with
  HTTP/3"*. HTTP/1.1 and HTTP/2 (Kestrel's default) are fine. HTTP/3 support is planned.
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
- Replicas coordinate through `IAcmeLock`: the holder orders, and every replica reads the store before ordering
  and again after taking the lock, so a certificate another replica just stored is used instead of ordered again.
- A background service orders, renews and stores certificates. The ACME client (RFC 8555, JWS/ES256) is written
  from scratch in a few hundred lines, so there is no dependency to go stale.

## Development

```
eng/pebble.sh        # or eng/pebble.ps1 on Windows; needs Go. Builds Let's Encrypt's test CA.
dotnet test
```

The Kubernetes tests need a cluster: `eng/kind.sh` creates a local one with kind (its own kubeconfig, your
kubectl context is untouched) and prints the `KESTRELACME_KUBERNETES` variable to set. Without it they're skipped.

The integration tests start Pebble and a real Kestrel app, then check issuance through each challenge type
(DNS-01 through Pebble's test DNS server), a wildcard certificate, the chain sent to clients, reuse after
restart, renewal triggered by ARI, and replicas sharing a store: one order between them, challenges answered by
the replica the CA reaches, and no retries by the others while the lock holder backs off. Pebble rejects 5% of nonces on
purpose, so the retry path runs every time. Without Pebble those tests are skipped. CI runs everything on
Linux, Windows and macOS, on .NET 8 and 10.

## License

[MIT](LICENSE)
