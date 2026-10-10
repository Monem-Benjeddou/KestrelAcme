using System.Security.Cryptography.X509Certificates;
using KestrelAcme.Certificates;
using Microsoft.Extensions.Options;

namespace KestrelAcme.Hosting;

/// <summary>Holds the certificate Kestrel serves. Swapping it takes effect on the next handshake.</summary>
internal sealed class CertificateSelector
{
    private readonly TimeProvider _time;
    private volatile CertificateBundle _current;

    public CertificateSelector(IOptions<AcmeOptions> options, TimeProvider time)
    {
        _time = time;
        var domains = options.Value.Domains;
        Placeholder = CertificateFactory.CreateFallback(domains.Count > 0 ? domains.ToList() : ["localhost"], time.GetUtcNow());
        _current = Placeholder;
    }

    /// <summary>
    /// The self-signed certificate served until a real one exists. It is also set as Kestrel's default HTTPS
    /// certificate, which is how endpoints that configured their own certificate are told apart.
    /// </summary>
    public CertificateBundle Placeholder { get; }

    public CertificateBundle Current => _current;

    /// <summary>Serves <paramref name="certificate"/> from the next handshake on, and retires the previous one.</summary>
    public void Use(CertificateBundle certificate)
    {
        var previous = Interlocked.Exchange(ref _current, certificate);
        if (!ReferenceEquals(previous, certificate))
            previous.Retire(_time);
    }

    public bool IsPlaceholder(X509Certificate? certificate) =>
        certificate is not null && certificate.GetCertHashString() == Placeholder.Leaf.GetCertHashString();
}
