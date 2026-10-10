using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace KestrelAcme.Certificates;

/// <summary>A certificate with its private key and intermediates, ready to hand to <see cref="System.Net.Security.SslStream"/>.</summary>
internal sealed class CertificateBundle : IDisposable
{
    /// <summary>How long a replaced certificate is kept alive for handshakes that already picked it.</summary>
    internal static readonly TimeSpan RetirementDelay = TimeSpan.FromMinutes(2);

    public CertificateBundle(X509Certificate2 leaf, X509Certificate2Collection intermediates, bool isFallback = false)
    {
        if (!leaf.HasPrivateKey)
            throw new ArgumentException("The certificate has no private key.", nameof(leaf));

        Leaf = leaf;
        Intermediates = intermediates;
        IsFallback = isFallback;
        DnsNames = CertificateFactory.GetDnsNames(leaf);

        // offline: true — the chain is complete already, so don't let SslStream fetch it over the network.
        Context = SslStreamCertificateContext.Create(leaf, intermediates, offline: true);
    }

    public X509Certificate2 Leaf { get; }
    public X509Certificate2Collection Intermediates { get; }
    public SslStreamCertificateContext Context { get; }
    public IReadOnlyList<string> DnsNames { get; }

    /// <summary>True for the self-signed certificate served until a real one has been issued.</summary>
    public bool IsFallback { get; }

    public DateTimeOffset NotBefore => Leaf.NotBefore.ToUniversalTime();
    public DateTimeOffset NotAfter => Leaf.NotAfter.ToUniversalTime();

    /// <summary>Whether the certificate covers exactly these names, in any order.</summary>
    public bool Covers(IEnumerable<string> domains) =>
        new HashSet<string>(DnsNames, StringComparer.OrdinalIgnoreCase).SetEquals(domains);

    public bool Matches(string serverName)
    {
        foreach (var name in DnsNames)
        {
            if (string.Equals(name, serverName, StringComparison.OrdinalIgnoreCase))
                return true;

            // "*.example.com" matches exactly one label: "a.example.com", not "a.b.example.com".
            if (name.StartsWith("*.", StringComparison.Ordinal))
            {
                var dot = serverName.IndexOf('.');
                if (dot > 0 && string.Equals(serverName[(dot + 1)..], name[2..], StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Disposes the certificates after <see cref="RetirementDelay"/>. On Windows this deletes the key files the
    /// PKCS#12 import wrote, which would otherwise pile up with every renewal and challenge.
    /// </summary>
    public void Retire(TimeProvider time)
    {
        if (IsFallback)
            return;
        _ = Task.Delay(RetirementDelay, time).ContinueWith(_ => Dispose(), TaskScheduler.Default);
    }

    public void Dispose()
    {
        Leaf.Dispose();
        foreach (var certificate in Intermediates)
            certificate.Dispose();
    }
}
