using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using KestrelAcme.Certificates;

namespace KestrelAcme.Tests;

public class CertificateFactoryTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    [Theory]
    [InlineData(CertificateKeyAlgorithm.EcdsaP256)]
    [InlineData(CertificateKeyAlgorithm.Rsa2048)]
    public void Signing_request_lists_every_domain(CertificateKeyAlgorithm algorithm)
    {
        var (csr, key) = CertificateFactory.CreateSigningRequest(["example.com", "www.example.com"], algorithm);
        using var _ = key;

        var request = CertificateRequest.LoadSigningRequest(csr, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        Assert.Equal("CN=example.com", request.SubjectName.Name);
        var san = Assert.Single(request.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>());
        Assert.Equal(["example.com", "www.example.com"], san.EnumerateDnsNames());
    }

    [Fact]
    public void Tls_alpn_challenge_certificate_carries_the_key_authorization_digest()
    {
        var bundle = CertificateFactory.CreateTlsAlpnChallenge("example.com", "token.thumbprint", Now);

        var extension = bundle.Leaf.Extensions[CertificateFactory.AcmeIdentifierOid];
        Assert.NotNull(extension);
        Assert.True(extension.Critical);

        var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
        Assert.Equal(SHA256.HashData(Encoding.ASCII.GetBytes("token.thumbprint")), reader.ReadOctetString());
        Assert.False(reader.HasData);
        Assert.Equal(["example.com"], bundle.DnsNames);
        Assert.True(bundle.Leaf.HasPrivateKey);
    }

    [Fact]
    public void Pem_chain_becomes_a_bundle_with_key_and_intermediates()
    {
        using var ca = TestCertificates.CreateAuthority("Test Intermediate");
        var (csr, key) = CertificateFactory.CreateSigningRequest(["example.com"], CertificateKeyAlgorithm.EcdsaP256);
        using var leaf = TestCertificates.Sign(ca, csr);
        var pem = leaf.ExportCertificatePem() + "\n" + ca.ExportCertificatePem() + "\n";

        var bundle = CertificateFactory.FromPemChain(pem, key);

        Assert.True(bundle.Leaf.HasPrivateKey);
        Assert.Equal(leaf.Thumbprint, bundle.Leaf.Thumbprint);
        Assert.Equal(ca.Thumbprint, Assert.Single(bundle.Intermediates).Thumbprint);
        Assert.False(bundle.IsFallback);
    }

    [Fact]
    public void Pfx_round_trip_keeps_the_chain()
    {
        using var ca = TestCertificates.CreateAuthority("Test Intermediate");
        var (csr, key) = CertificateFactory.CreateSigningRequest(["example.com"], CertificateKeyAlgorithm.EcdsaP256);
        using var leaf = TestCertificates.Sign(ca, csr);
        var bundle = CertificateFactory.FromPemChain(leaf.ExportCertificatePem() + "\n" + ca.ExportCertificatePem(), key);

        var reloaded = CertificateFactory.FromPfx(CertificateFactory.ToPfx(bundle));

        // .NET 8 on Windows deleted keys imported through a collection at the next GC, while still in use.
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        reloaded.Leaf.GetECDsaPrivateKey()!.SignData([1, 2, 3], HashAlgorithmName.SHA256);
        Assert.NotEmpty(CertificateFactory.ToPfx(reloaded));

        Assert.Equal(bundle.Leaf.Thumbprint, reloaded.Leaf.Thumbprint);
        Assert.True(reloaded.Leaf.HasPrivateKey);
        Assert.Equal(ca.Thumbprint, Assert.Single(reloaded.Intermediates).Thumbprint);
    }

    [Fact]
    public void Renewal_id_matches_the_rfc9773_example()
    {
        // RFC 9773 §4.1: keyIdentifier 69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4, serial 00:87:65:43:21.
        byte[] keyId = Convert.FromHexString("69885B6B87464041E1B37B847BA0AE2CDE01C8D4");
        byte[] serial = Convert.FromHexString("0087654321");

        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var subjectKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=example.com", subjectKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(keyId));
        using var certificate = request.Create(
            new X500DistinguishedName("CN=Issuer"), X509SignatureGenerator.CreateForECDsa(issuerKey), Now.AddDays(-1), Now.AddDays(1), serial);

        Assert.Equal("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE", CertificateFactory.GetRenewalId(certificate));
    }

    [Fact]
    public void Renewal_id_is_null_without_authority_key_identifier()
    {
        var fallback = CertificateFactory.CreateFallback(["example.com"], Now);
        Assert.Null(CertificateFactory.GetRenewalId(fallback.Leaf));
    }

    [Fact]
    public void Fallback_is_self_signed_marked_and_usable_for_tls()
    {
        var fallback = CertificateFactory.CreateFallback(["example.com", "www.example.com"], Now);

        Assert.True(fallback.IsFallback);
        Assert.True(fallback.Leaf.HasPrivateKey);
        Assert.True(fallback.Covers(["www.example.com", "EXAMPLE.com"]));
        Assert.Contains(fallback.Leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages.Cast<Oid>(),
            oid => oid.Value == "1.3.6.1.5.5.7.3.1");
    }

    [Theory]
    [InlineData("example.com", true)]
    [InlineData("EXAMPLE.COM", true)]
    [InlineData("a.wild.example", true)]
    [InlineData("a.b.wild.example", false)]
    [InlineData("wild.example", false)]
    [InlineData("other.com", false)]
    public void Matches_exact_names_and_one_wildcard_label(string serverName, bool expected)
    {
        var bundle = CertificateFactory.CreateFallback(["example.com", "*.wild.example"], Now);
        Assert.Equal(expected, bundle.Matches(serverName));
    }
}

internal static class TestCertificates
{
    public static X509Certificate2 CreateAuthority(string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    public static X509Certificate2 Sign(X509Certificate2 authority, byte[] csr, TimeSpan? lifetime = null)
    {
        var request = CertificateRequest.LoadSigningRequest(csr, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(authority, true, false));
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-1);
        return request.Create(authority, notBefore, notBefore + (lifetime ?? TimeSpan.FromDays(90)), RandomNumberGenerator.GetBytes(8));
    }
}
