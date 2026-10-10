using System.Collections.Concurrent;
using KestrelAcme.Certificates;

namespace KestrelAcme.Hosting;

/// <summary>The challenge responses currently being served, while an order is in progress.</summary>
internal sealed class ChallengeResponder
{
    public const string AcmeTlsProtocol = "acme-tls/1";
    public const string Http01PathPrefix = "/.well-known/acme-challenge/";

    private readonly ConcurrentDictionary<string, string> _http01 = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CertificateBundle> _tlsAlpn01 = new(StringComparer.OrdinalIgnoreCase);

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
}
