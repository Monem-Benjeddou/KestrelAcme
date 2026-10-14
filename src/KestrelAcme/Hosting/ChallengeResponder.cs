using System.Collections.Concurrent;
using System.Text;
using KestrelAcme.Certificates;
using KestrelAcme.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace KestrelAcme.Hosting;

/// <summary>
/// The challenge responses currently being served, while an order is in progress. Answers are also shared through
/// the store, so another instance behind the same load balancer can answer when the certificate authority reaches it.
/// </summary>
internal sealed class ChallengeResponder(IAcmeStore store, IOptions<AcmeOptions> options, TimeProvider time, ILogger<ChallengeResponder> logger)
{
    public const string AcmeTlsProtocol = "acme-tls/1";
    public const string Http01PathPrefix = "/.well-known/acme-challenge/";

    private readonly ConcurrentDictionary<string, string> _http01 = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CertificateBundle> _tlsAlpn01 = new(StringComparer.OrdinalIgnoreCase);

    // Anyone can ask for a made-up token: bound how many of those reach the store at once.
    private readonly SemaphoreSlim _storeLookups = new(4, 4);

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

    public string Http01Key(string token) => $"challenges/{AcmeCertificateIssuer.StoreName(options.Value.DirectoryUri)}/http-01/{token}";

    public string TlsAlpn01Key(string domain) => $"challenges/{AcmeCertificateIssuer.StoreName(options.Value.DirectoryUri)}/tls-alpn-01/{domain}";

    /// <summary>The answer for an HTTP-01 token: this instance's, or one another instance shared.</summary>
    public async Task<string?> FindHttp01Async(string token, CancellationToken cancellationToken)
    {
        if (TryGetHttp01(token, out var keyAuthorization))
            return keyAuthorization;
        if (!IsToken(token))
            return null;
        return await ReadSharedAsync(Http01Key(token), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// A TLS-ALPN-01 certificate built from an answer another instance shared, or null. The caller disposes it.
    /// </summary>
    public async Task<CertificateBundle?> LoadSharedTlsAlpn01Async(string domain, CancellationToken cancellationToken)
    {
        if (!IsHostName(domain))
            return null;
        var keyAuthorization = await ReadSharedAsync(TlsAlpn01Key(domain.ToLowerInvariant()), cancellationToken).ConfigureAwait(false);
        return keyAuthorization is null ? null : CertificateFactory.CreateTlsAlpnChallenge(domain, keyAuthorization, time.GetUtcNow());
    }

    /// <summary>Publishes an answer for other instances. Best effort: this instance answers from memory regardless.</summary>
    public async Task ShareAsync(string key, string keyAuthorization, CancellationToken cancellationToken)
    {
        try
        {
            await store.WriteAsync(key, Encoding.ASCII.GetBytes(keyAuthorization), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Log.ChallengeShareFailed(logger, e);
        }
    }

    public Task UnshareAsync(string key) => store.DeleteAsync(key, CancellationToken.None);

    private async Task<string?> ReadSharedAsync(string key, CancellationToken cancellationToken)
    {
        if (!_storeLookups.Wait(0))
            return null;
        try
        {
            var value = await store.ReadAsync(key, cancellationToken).ConfigureAwait(false);
            return value is null ? null : Encoding.ASCII.GetString(value);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Log.ChallengeLookupFailed(logger, key, e);
            return null;
        }
        finally
        {
            _storeLookups.Release();
        }
    }

    /// <summary>A challenge token: base64url, at least 128 bits (RFC 8555 §8.3). Anything else never reaches the store.</summary>
    internal static bool IsToken(string token) =>
        token.Length is >= 22 and <= 128 && token.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>An ASCII host name, as sent in SNI. Anything else never reaches the store.</summary>
    internal static bool IsHostName(string name) =>
        name.Length is > 0 and <= 253 && name[0] != '.' && !name.Contains("..", StringComparison.Ordinal)
        && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.');
}
