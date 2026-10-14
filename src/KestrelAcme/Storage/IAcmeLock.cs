namespace KestrelAcme.Storage;

/// <summary>
/// Lets several instances of an app (replicas behind a load balancer) agree on which one orders the certificate.
/// The holder orders and stores it; the others wait and pick it up from the shared <see cref="IAcmeStore"/>.
/// </summary>
/// <remarks>
/// The default locks a file next to the certificate, which coordinates instances sharing <see cref="AcmeOptions.StoragePath"/>
/// on a volume that supports file locks (local disk, NFSv4, SMB/Azure Files, EFS). Register your own implementation
/// when certificates live in a custom <see cref="IAcmeStore"/>: without one, instances using it don't coordinate.
/// A lock is held from the start of an order until it succeeds, retries included, so it can be held for hours.
/// Implementations whose locks expire must keep them alive until the handle is disposed, and expire them soon after
/// a holder disappears without disposing it.
/// </remarks>
public interface IAcmeLock
{
    /// <summary>Takes the lock without waiting.</summary>
    /// <param name="name">The lock name, a store key such as <c>certificates/acme-v02.api.letsencrypt.org_directory/example.com.pfx</c>.</param>
    /// <param name="cancellationToken">Stops the attempt.</param>
    /// <returns>A handle that releases the lock when disposed, or <see langword="null"/> if another instance holds it.</returns>
    Task<IAsyncDisposable?> TryAcquireAsync(string name, CancellationToken cancellationToken);
}

/// <summary>
/// A held lock that can be lost before it is released (an expiring lease that couldn't be renewed). The order in
/// progress is abandoned when <see cref="Lost"/> fires, so it doesn't run alongside the next holder's.
/// </summary>
internal interface ILosableLock
{
    CancellationToken Lost { get; }
}
