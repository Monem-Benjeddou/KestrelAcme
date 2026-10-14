using Microsoft.Extensions.Logging;

namespace KestrelAcme.Storage;

/// <summary>
/// Locks a file next to the certificate, exclusively. The operating system releases the lock when the process exits,
/// so an instance that crashes never leaves it held, and no clock is involved.
/// </summary>
/// <remarks>
/// Uses the platform's file locks (<c>flock</c> on Linux and macOS, share modes on Windows), which NFSv4, SMB/Azure
/// Files and EFS honour across machines. Setting <c>DOTNET_SYSTEM_IO_DISABLEFILELOCKING</c> turns them off.
/// </remarks>
internal sealed class FileSystemAcmeLock(FileSystemAcmeStore store) : IAcmeLock
{
    public Task<IAsyncDisposable?> TryAcquireAsync(string name, CancellationToken cancellationToken)
    {
        var path = store.Resolve(name + ".lock");
        FileSystemAcmeStore.CreateDirectory(Path.GetDirectoryName(path)!);

        // The file is never deleted: an instance waiting on a deleted file and one creating its replacement would
        // each lock a different file.
        var options = new FileStreamOptions { Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = FileSystemAcmeStore.OwnerOnlyFile;

        try
        {
            return Task.FromResult<IAsyncDisposable?>(new FileStream(path, options));
        }
        catch (IOException e) when (IsHeldElsewhere(e))
        {
            return Task.FromResult<IAsyncDisposable?>(null);
        }
    }

    // Windows: ERROR_SHARING_VIOLATION or ERROR_LOCK_VIOLATION. Linux and macOS: EWOULDBLOCK from flock (11 and 35).
    // Any other I/O error is a real failure and must not pass for "someone else is renewing".
    private static bool IsHeldElsewhere(IOException e) =>
        e.HResult is unchecked((int)0x80070020) or unchecked((int)0x80070021)
        || (!OperatingSystem.IsWindows() && e.HResult == (OperatingSystem.IsLinux() ? 11 : 35));
}

/// <summary>
/// The lock used with a custom <see cref="IAcmeStore"/> when no <see cref="IAcmeLock"/> is registered: always granted,
/// so a single instance works as before and several instances don't coordinate.
/// </summary>
internal sealed class UncoordinatedAcmeLock(IAcmeStore store, ILogger<UncoordinatedAcmeLock> logger) : IAcmeLock, IAsyncDisposable
{
    private int _logged;

    public Task<IAsyncDisposable?> TryAcquireAsync(string name, CancellationToken cancellationToken)
    {
        // Said once, when the first order starts: running replicas on such a store silently ordered per replica.
        if (Interlocked.Exchange(ref _logged, 1) == 0)
            Log.Uncoordinated(logger, store.GetType().Name);
        return Task.FromResult<IAsyncDisposable?>(this);
    }

    public ValueTask DisposeAsync() => default;
}
