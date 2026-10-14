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
/// a holder disappears without disposing it. If such a lock can be lost while held (it couldn't be renewed), the
/// handle should implement <see cref="IAcmeLockHandle"/>, so the order in progress stops before another instance's starts.
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
/// Optionally implemented by the handle <see cref="IAcmeLock.TryAcquireAsync"/> returns, for locks that can be lost
/// before they are released (an expiring lease that couldn't be renewed).
/// </summary>
public interface IAcmeLockHandle : IAsyncDisposable
{
    /// <summary>
    /// Cancelled once the lock is lost, or might be: the order in progress is then abandoned, so it doesn't run
    /// alongside the next holder's. Cancel it before another instance can take the lock over.
    /// </summary>
    CancellationToken Lost { get; }
}
