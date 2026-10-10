using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using KestrelAcme.Protocol;

namespace KestrelAcme.Certificates;

internal static class CertificateFactory
{
    /// <summary>id-pe-acmeIdentifier, the critical extension of a TLS-ALPN-01 challenge certificate (RFC 8737 §3).</summary>
    internal const string AcmeIdentifierOid = "1.3.6.1.5.5.7.1.31";

    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    private const string AuthorityKeyIdentifierOid = "2.5.29.35";

    /// <summary>Creates a new key and a certificate signing request for <paramref name="domains"/> (DER).</summary>
    public static (byte[] Csr, AsymmetricAlgorithm Key) CreateSigningRequest(
        IReadOnlyList<string> domains, CertificateKeyAlgorithm algorithm)
    {
        var subject = new X500DistinguishedName($"CN={domains[0]}");
        AsymmetricAlgorithm key;
        CertificateRequest request;

        switch (algorithm)
        {
            case CertificateKeyAlgorithm.EcdsaP256 or CertificateKeyAlgorithm.EcdsaP384:
                var ecdsa = ECDsa.Create(algorithm == CertificateKeyAlgorithm.EcdsaP256
                    ? ECCurve.NamedCurves.nistP256
                    : ECCurve.NamedCurves.nistP384);
                key = ecdsa;
                request = new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);
                break;
            case CertificateKeyAlgorithm.Rsa2048 or CertificateKeyAlgorithm.Rsa4096:
                var rsa = RSA.Create(algorithm == CertificateKeyAlgorithm.Rsa2048 ? 2048 : 4096);
                key = rsa;
                request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null);
        }

        request.CertificateExtensions.Add(BuildSubjectAlternativeNames(domains));
        return (request.CreateSigningRequest(), key);
    }

    /// <summary>Combines the PEM chain the certificate authority returned with the private key generated for the CSR.</summary>
    public static CertificateBundle FromPemChain(string pemChain, AsymmetricAlgorithm key)
    {
        var chain = new X509Certificate2Collection();
        chain.ImportFromPem(pemChain);
        if (chain.Count == 0)
            throw new AcmeException("The certificate authority returned no certificate.");

        // RFC 8555 §9.1: the end-entity certificate comes first, then the chain.
        using var leaf = chain[0];
        using var withKey = key switch
        {
            ECDsa ecdsa => leaf.CopyWithPrivateKey(ecdsa),
            RSA rsa => leaf.CopyWithPrivateKey(rsa),
            _ => throw new ArgumentException($"Unsupported key type {key.GetType().Name}.", nameof(key)),
        };

        var export = new X509Certificate2Collection(withKey);
        for (var i = 1; i < chain.Count; i++)
            export.Add(chain[i]);

        // Round-trip through PKCS#12: on Windows, SChannel can't use the ephemeral key CopyWithPrivateKey makes.
        var bundle = FromPfx(export.Export(X509ContentType.Pkcs12)!);
        for (var i = 1; i < chain.Count; i++)
            chain[i].Dispose();
        return bundle;
    }

    public static byte[] ToPfx(CertificateBundle bundle)
    {
        var collection = new X509Certificate2Collection(bundle.Leaf);
        collection.AddRange(bundle.Intermediates);
        return collection.Export(X509ContentType.Pkcs12)!;
    }

    public static CertificateBundle FromPfx(byte[] pfx, bool isFallback = false)
    {
        var collection = LoadPkcs12(pfx);
        X509Certificate2? leaf = null;
        var intermediates = new X509Certificate2Collection();
        foreach (var certificate in collection)
        {
            if (leaf is null && certificate.HasPrivateKey)
                leaf = certificate;
            else
                intermediates.Add(certificate);
        }

        return new CertificateBundle(
            leaf ?? throw new CryptographicException("The PKCS#12 data contains no certificate with a private key."),
            intermediates,
            isFallback);
    }

    private static X509Certificate2Collection LoadPkcs12(byte[] pfx)
    {
        // Exportable: the bundle is written back to the store after issuance, and macOS and Windows refuse to
        // export a key imported without it. Not EphemeralKeySet: SChannel can't use ephemeral keys.
        try
        {
            return LoadPkcs12(pfx, X509KeyStorageFlags.Exportable);
        }
        catch (CryptographicException) when (OperatingSystem.IsWindows())
        {
            // Accounts without a loaded user profile (some service accounts, IIS app pools with
            // LoadUserProfile=false) have no user key store. The machine key store works for them.
            return LoadPkcs12(pfx, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        }
    }

    private static X509Certificate2Collection LoadPkcs12(byte[] pfx, X509KeyStorageFlags flags)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12Collection(pfx, password: null, flags);
#else
        var collection = new X509Certificate2Collection();
        collection.Import(pfx, password: null, flags);
        return collection;
#endif
    }

    /// <summary>A self-signed certificate served while no real certificate exists yet, so handshakes don't fail outright.</summary>
    public static CertificateBundle CreateFallback(IReadOnlyList<string> domains, DateTimeOffset now)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={domains[0]}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(BuildSubjectAlternativeNames(domains));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ServerAuthOid)], critical: false));

        using var certificate = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(7));
        return FromPfx(certificate.Export(X509ContentType.Pkcs12), isFallback: true);
    }

    /// <summary>The certificate that answers a TLS-ALPN-01 challenge for <paramref name="domain"/> (RFC 8737 §3).</summary>
    public static CertificateBundle CreateTlsAlpnChallenge(string domain, string keyAuthorization, DateTimeOffset now)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={domain}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(BuildSubjectAlternativeNames([domain]));

        // The extension value is an OCTET STRING holding the SHA-256 of the key authorization.
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(SHA256.HashData(Encoding.ASCII.GetBytes(keyAuthorization)));
        request.CertificateExtensions.Add(new X509Extension(AcmeIdentifierOid, writer.Encode(), critical: true));

        using var certificate = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(7));
        return FromPfx(certificate.Export(X509ContentType.Pkcs12));
    }

    /// <summary>
    /// The ARI certificate identifier (RFC 9773 §4.1): base64url of the authority key identifier, a dot,
    /// and base64url of the serial number bytes. Null if the certificate has no authority key identifier.
    /// </summary>
    public static string? GetRenewalId(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions[AuthorityKeyIdentifierOid];
        if (extension is null)
            return null;

        var authorityKeyId = new X509AuthorityKeyIdentifierExtension(extension.RawData, extension.Critical).KeyIdentifier;
        if (authorityKeyId is not { Length: > 0 } keyId)
            return null;

        return $"{Base64Url.Encode(keyId.Span)}.{Base64Url.Encode(certificate.SerialNumberBytes.Span)}";
    }

    public static IReadOnlyList<string> GetDnsNames(X509Certificate2 certificate)
    {
        foreach (var extension in certificate.Extensions)
        {
            if (extension is X509SubjectAlternativeNameExtension san)
                return san.EnumerateDnsNames().ToList();
            if (extension.Oid?.Value == "2.5.29.17")
                return new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical).EnumerateDnsNames().ToList();
        }
        return [];
    }

    private static X509Extension BuildSubjectAlternativeNames(IEnumerable<string> domains)
    {
        var builder = new SubjectAlternativeNameBuilder();
        foreach (var domain in domains)
            builder.AddDnsName(domain);
        return builder.Build();
    }
}
