using System.Collections.Concurrent;
using System.Text;
using KestrelAcme.Certificates;
using KestrelAcme.Protocol;
using KestrelAcme.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace KestrelAcme.Hosting;

/// <summary>
/// The challenge responses currently being served, while an order is in progress. When instances coordinate, the
/// ordering one also publishes its answers to the store, so another instance behind the same load balancer can answer
/// when the certificate authority reaches it.
/// </summary>
internal sealed class ChallengeResponder(
    IAcmeStore store, IAcmeLock acmeLock, IOptions<AcmeOptions> options, TimeProvider time, ILogger<ChallengeResponder> logger)
{
    public const string AcmeTlsProtocol = "acme-tls/1";
    public const string Http01PathPrefix = "/.well-known/acme-challenge/";

    /// <summary>
    /// How long the ordering instance waits between publishing its answers and letting the CA check them. Longer than
    /// <see cref="MinRefreshInterval"/>, so an instance whose copy predates the publication reads it again in time.
    /// </summary>
    internal static readonly TimeSpan PublishDelay = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Instances read the published answers at most this often, however many requests come in: anyone can ask for a
    /// made-up token, and those requests must not turn into a stream of store (or Kubernetes API) reads.
    /// </summary>
    internal static readonly TimeSpan MinRefreshInterval = TimeSpan.FromSeconds(1);

    private static readonly TimeSpan RefreshTimeout = TimeSpan.FromSeconds(10);

    private readonly ConcurrentDictionary<string, string> _http01 = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CertificateBundle> _tlsAlpn01 = new(StringComparer.OrdinalIgnoreCase);

    private readonly object _gate = new();
    private volatile Dictionary<string, string> _published = [];
    private long _refreshedAt;
    private Task _refreshing = Task.CompletedTask;

    /// <summary>
    /// Whether answers go through the store. Not with a custom store that has no lock: those instances don't
    /// coordinate, and the store is left as it was before multi-instance support.
    /// </summary>
    public bool Shares { get; } = acmeLock is not UncoordinatedAcmeLock;

    public void AddHttp01(string token, string keyAuthorization) => _http01[token] = keyAuthorization;

    public void RemoveHttp01(string token) => _http01.TryRemove(token, out _);

    public bool TryGetHttp01(string token, out string keyAuthorization) =>
        _http01.TryGetValue(token, out keyAuthorization!);

    public void AddTlsAlpn01(string domain, CertificateBundle certificate) => _tlsAlpn01[domain] = certificate;

    public bool RemoveTlsAlpn01(string domain, out CertificateBundle certificate) =>
        _tlsAlpn01.TryRemove(domain, out certificate!);

    public bool TryGetTlsAlpn01(string? domain, out CertificateBundle certificate)
    {
        certificate = null!;
        return domain is not null && _tlsAlpn01.TryGetValue(domain, out certificate!);
    }

    /// <summary>One key per certificate: every instance serving it reads the same one.</summary>
    public string PublishedKey =>
        $"challenges/{AcmeCertificateIssuer.StoreName(options.Value.DirectoryUri)}/{AcmeCertificateIssuer.FileName(options.Value.Domains[0])}.txt";

    /// <summary>Publishes an order's HTTP-01 tokens and TLS-ALPN-01 domains with their key authorizations.</summary>
    public async Task PublishAsync(IReadOnlyCollection<SharedAnswer> answers, CancellationToken cancellationToken)
    {
        var text = new StringBuilder();
        foreach (var answer in answers)
            text.Append(answer.Type).Append(' ').Append(answer.Id).Append(' ').Append(answer.KeyAuthorization).Append('\n');
        try
        {
            await store.WriteAsync(PublishedKey, Encoding.ASCII.GetBytes(text.ToString()), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Log.ChallengeShareFailed(logger, e); // this instance still answers from memory
        }
    }

    public Task UnpublishAsync() => store.DeleteAsync(PublishedKey, CancellationToken.None);

    /// <summary>The answer for an HTTP-01 token: this instance's, or one another instance published.</summary>
    public async Task<string?> FindHttp01Async(string token, CancellationToken cancellationToken)
    {
        if (TryGetHttp01(token, out var keyAuthorization))
            return keyAuthorization;
        return Shares && IsToken(token)
            ? await FindPublishedAsync($"{AcmeChallenge.Http01} {token}", cancellationToken).ConfigureAwait(false)
            : null;
    }

    /// <summary>
    /// A TLS-ALPN-01 certificate built from an answer another instance published, or null. The caller disposes it.
    /// </summary>
    public async Task<CertificateBundle?> LoadSharedTlsAlpn01Async(string domain, CancellationToken cancellationToken)
    {
        if (!Shares || !IsHostName(domain))
            return null;
        domain = domain.ToLowerInvariant();
        var keyAuthorization = await FindPublishedAsync($"{AcmeChallenge.TlsAlpn01} {domain}", cancellationToken).ConfigureAwait(false);
        return keyAuthorization is null ? null : CertificateFactory.CreateTlsAlpnChallenge(domain, keyAuthorization, time.GetUtcNow());
    }

    /// <summary>
    /// Looks in this instance's copy of the published answers, reading the store again on a miss if the last read
    /// started at least <see cref="MinRefreshInterval"/> ago. Concurrent misses share one read.
    /// </summary>
    private async Task<string?> FindPublishedAsync(string id, CancellationToken cancellationToken)
    {
        if (_published.TryGetValue(id, out var keyAuthorization))
            return keyAuthorization;

        Task refresh;
        lock (_gate)
        {
            // A completed task, not null, marks "no read running": a read that completes synchronously would otherwise
            // clear the field before it is set, and block every later read.
            if (_refreshing.IsCompleted && time.GetElapsedTime(_refreshedAt) >= MinRefreshInterval)
            {
                _refreshedAt = time.GetTimestamp();
                _refreshing = RefreshAsync();
            }
            refresh = _refreshing;
        }

        await refresh.WaitAsync(cancellationToken).ConfigureAwait(false);
        return _published.GetValueOrDefault(id);
    }

    private async Task RefreshAsync()
    {
        try
        {
            // Not tied to the request that triggered it: others may be waiting on the same read.
            using var timeout = new CancellationTokenSource(RefreshTimeout, time);
            var value = await store.ReadAsync(PublishedKey, timeout.Token).ConfigureAwait(false);

            var published = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var line in Encoding.ASCII.GetString(value ?? []).Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = line.Split(' ');
                if (parts.Length == 3)
                    published[$"{parts[0]} {parts[1]}"] = parts[2];
            }
            _published = published;
        }
        catch (Exception e)
        {
            Log.ChallengeLookupFailed(logger, PublishedKey, e);
        }
    }

    /// <summary>A challenge token: base64url, at least 128 bits (RFC 8555 §8.3). Anything else is never looked up.</summary>
    internal static bool IsToken(string token) =>
        token.Length is >= 22 and <= 128 && token.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>An ASCII host name, as sent in SNI. Anything else is never looked up.</summary>
    internal static bool IsHostName(string name) =>
        name.Length is > 0 and <= 253 && name[0] != '.' && !name.Contains("..", StringComparison.Ordinal)
        && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.');
}

/// <summary>An answer another instance may have to give: an HTTP-01 token or a TLS-ALPN-01 domain, and its key authorization.</summary>
internal sealed record SharedAnswer(string Type, string Id, string KeyAuthorization);
