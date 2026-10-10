namespace KestrelAcme.Storage;

/// <summary>
/// Persists the ACME account key and issued certificates. Register your own implementation to keep them in
/// Key Vault, a database or blob storage; the default writes files under <see cref="AcmeOptions.StoragePath"/>.
/// </summary>
/// <remarks>
/// Keys are relative paths with forward slashes, one folder per CA directory, such as
/// <c>accounts/acme-v02.api.letsencrypt.org_directory/account.pem</c> (PEM, the account key) and
/// <c>certificates/acme-v02.api.letsencrypt.org_directory/example.com.pfx</c> (PKCS#12, certificate, chain and key).
/// Values contain private keys: store them with care. Members added in later versions will have default
/// implementations, so implementing this interface stays source-compatible.
/// </remarks>
public interface IAcmeStore
{
    /// <summary>Returns the stored value, or <see langword="null"/> if there is none.</summary>
    Task<byte[]?> ReadAsync(string key, CancellationToken cancellationToken);

    /// <summary>Stores a value, replacing any existing one.</summary>
    Task WriteAsync(string key, byte[] value, CancellationToken cancellationToken);
}
