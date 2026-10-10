namespace KestrelAcme;

/// <summary>Settings for obtaining and renewing certificates from an ACME certificate authority.</summary>
public sealed class AcmeOptions
{
    /// <summary>The domain names the certificate covers. The first one becomes the subject.</summary>
    public IList<string> Domains { get; } = new List<string>();

    /// <summary>Contact address the certificate authority uses for expiry and policy notices. Optional.</summary>
    public string? Email { get; set; }

    /// <summary>
    /// Must be <see langword="true"/>: confirms you accept the certificate authority's subscriber agreement
    /// (for Let's Encrypt: https://letsencrypt.org/repository/).
    /// </summary>
    public bool AcceptTermsOfService { get; set; }

    /// <summary>The ACME directory URL. Defaults to Let's Encrypt production.</summary>
    public Uri DirectoryUri { get; set; } = AcmeDirectories.LetsEncrypt;

    /// <summary>Which challenge types may be used to prove control of the domains.</summary>
    public AcmeChallengeTypes Challenges { get; set; } = AcmeChallengeTypes.Http01 | AcmeChallengeTypes.TlsAlpn01;

    /// <summary>The key type of the issued certificate.</summary>
    public CertificateKeyAlgorithm KeyAlgorithm { get; set; } = CertificateKeyAlgorithm.EcdsaP256;

    /// <summary>
    /// Certificate profile to request, such as <c>"shortlived"</c> on Let's Encrypt.
    /// Leave empty to use the certificate authority's default.
    /// </summary>
    public string? Profile { get; set; }

    /// <summary>
    /// Renew when less than this much validity is left. When <see langword="null"/> (the default), the certificate
    /// authority's renewal window (ARI) is used, or one third of the lifetime if it doesn't provide one.
    /// </summary>
    public TimeSpan? RenewBefore { get; set; }

    /// <summary>Directory for the account key and certificates. Defaults to a folder under the user's profile.</summary>
    public string? StoragePath { get; set; }

    /// <summary>External account binding, required by some certificate authorities (ZeroSSL, Google Trust Services).</summary>
    public ExternalAccountBinding? ExternalAccountBinding { get; set; }

    /// <summary>How long to wait for the certificate authority to validate challenges and issue the certificate.</summary>
    public TimeSpan IssuanceTimeout { get; set; } = TimeSpan.FromMinutes(5);
}

/// <summary>Well-known ACME directory URLs.</summary>
public static class AcmeDirectories
{
    /// <summary>Let's Encrypt production. Certificates are trusted by browsers; rate limits apply.</summary>
    public static readonly Uri LetsEncrypt = new("https://acme-v02.api.letsencrypt.org/directory");

    /// <summary>Let's Encrypt staging. Untrusted certificates, much higher rate limits. Use it while testing.</summary>
    public static readonly Uri LetsEncryptStaging = new("https://acme-staging-v02.api.letsencrypt.org/directory");
}

/// <summary>Challenge types used to prove control of a domain.</summary>
[Flags]
public enum AcmeChallengeTypes
{
    /// <summary>None.</summary>
    None = 0,

    /// <summary>The certificate authority fetches a token over plain HTTP on port 80.</summary>
    Http01 = 1,

    /// <summary>The certificate authority connects on port 443 with the <c>acme-tls/1</c> protocol (RFC 8737).</summary>
    TlsAlpn01 = 2,
}

/// <summary>Key type of the issued certificate.</summary>
public enum CertificateKeyAlgorithm
{
    /// <summary>ECDSA on the P-256 curve. Small, fast and supported by every modern client.</summary>
    EcdsaP256,

    /// <summary>ECDSA on the P-384 curve.</summary>
    EcdsaP384,

    /// <summary>RSA with a 2048-bit key, for old clients.</summary>
    Rsa2048,

    /// <summary>RSA with a 4096-bit key.</summary>
    Rsa4096,
}

/// <summary>Credentials that link the ACME account to an existing account at the certificate authority (RFC 8555 §7.3.4).</summary>
/// <param name="KeyId">The key identifier given by the certificate authority.</param>
/// <param name="HmacKey">The HMAC key given by the certificate authority, base64url-encoded.</param>
public sealed record ExternalAccountBinding(string KeyId, string HmacKey);
