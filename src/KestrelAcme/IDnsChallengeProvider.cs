namespace KestrelAcme;

/// <summary>
/// Creates and deletes the DNS TXT records of the DNS-01 challenge (RFC 8555 §8.4), through your DNS host's API.
/// Needed for wildcard certificates (<c>*.example.com</c>); also works when ports 80 and 443 aren't reachable
/// from the internet. Register an implementation with
/// <c>services.AddSingleton&lt;IDnsChallengeProvider, MyProvider&gt;()</c>.
/// </summary>
/// <remarks>
/// The same record name can receive two values at once (for <c>example.com</c> and <c>*.example.com</c>), so
/// add records rather than replacing them, and delete only the given value.
/// </remarks>
public interface IDnsChallengeProvider
{
    /// <summary>Creates a TXT record.</summary>
    /// <param name="name">Fully qualified record name without the trailing dot, e.g. <c>_acme-challenge.example.com</c>.</param>
    /// <param name="value">The record value, to be served exactly as given.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    Task AddTxtRecordAsync(string name, string value, CancellationToken cancellationToken);

    /// <summary>Deletes the TXT record created by <see cref="AddTxtRecordAsync"/> with this name and value.</summary>
    /// <param name="name">The record name.</param>
    /// <param name="value">The record value.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    Task RemoveTxtRecordAsync(string name, string value, CancellationToken cancellationToken);
}
