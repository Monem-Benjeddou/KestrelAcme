using KestrelAcme.Certificates;
using KestrelAcme.Diagnostics;
using KestrelAcme.Protocol;
using KestrelAcme.Storage;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace KestrelAcme.Hosting;

/// <summary>
/// Loads the stored certificate before Kestrel starts, then keeps it valid: issues one if there is none,
/// and renews it when the CA's renewal window (or the configured margin) is reached.
/// </summary>
/// <remarks>
/// Instances sharing a store take turns through <see cref="IAcmeLock"/>: one orders, the others wait and pick up
/// the certificate it stores.
/// </remarks>
internal sealed class AcmeRenewalService(
    AcmeCertificateIssuer issuer,
    IAcmeStore store,
    IAcmeLock renewalLock,
    CertificateSelector selector,
    AcmeMetrics metrics,
    IHostApplicationLifetime lifetime,
    IOptions<AcmeOptions> options,
    TimeProvider time,
    ILogger<AcmeRenewalService> logger) : BackgroundService, IHostedLifecycleService
{
    private static readonly TimeSpan SaveTimeout = TimeSpan.FromSeconds(30);

    /// <summary>How soon an instance that found the lock taken looks again, for the certificate or the lock.</summary>
    internal static readonly TimeSpan LockedRetry = TimeSpan.FromSeconds(30);

    private readonly SemaphoreSlim _wake = new(0, 1);

    // Picked once per certificate, so the moment inside the CA's window doesn't move every time we look.
    private double _windowPosition = Random.Shared.NextDouble();

    // An issued certificate the store failed to save; saving is retried on every check.
    private CertificateBundle? _unsaved;

    // Taken when an order is due and kept until one succeeds, through retries: other instances must neither order
    // the same certificate nor multiply failed attempts (and the CA's rate limits) while this one backs off.
    private IAsyncDisposable? _lock;

    private AcmeOptions Options => options.Value;

    /// <summary>Makes the service look at the certificate now instead of at the next scheduled check.</summary>
    public void RequestCheck()
    {
        try
        {
            _wake.Release();
        }
        catch (SemaphoreFullException)
        {
            // A check is already requested.
        }
    }

    /// <summary>Runs before any hosted service starts (Kestrel included), so the first handshake gets the stored certificate.</summary>
    public Task StartingAsync(CancellationToken cancellationToken) => LoadStoredAsync(startup: true, cancellationToken);

    /// <summary>
    /// Serves the stored certificate if it is newer than the one being served: at startup, and after another
    /// instance renewed. Returns whether it did.
    /// </summary>
    private async Task<bool> LoadStoredAsync(bool startup, CancellationToken cancellationToken)
    {
        CertificateBundle certificate;
        try
        {
            var pfx = await store.ReadAsync(issuer.CertificateKey, cancellationToken).ConfigureAwait(false);
            if (pfx is null)
            {
                if (startup)
                    Log.NoStoredCertificate(logger);
                return false;
            }
            certificate = CertificateFactory.FromPfx(pfx);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Log.StoredCertificateUnreadable(logger, e);
            return false;
        }

        var current = selector.Current;
        var ignored = !certificate.Covers(Options.Domains) ? "it covers other domains"
            : certificate.NotAfter <= time.GetUtcNow() ? "it has expired"
            : null;

        // NotBefore, not NotAfter: a newer certificate can expire sooner, after a switch to a shorter profile.
        if (ignored is null && (current.IsFallback || !current.Covers(Options.Domains) || certificate.NotBefore > current.NotBefore))
        {
            selector.Use(certificate);
            Log.LoadedCertificate(logger, string.Join(", ", certificate.DnsNames), certificate.NotAfter);
            return true;
        }

        if (startup && ignored is not null)
            Log.StoredCertificateIgnored(logger, ignored);
        certificate.Dispose();
        return false;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // HTTP-01 and TLS-ALPN-01 need Kestrel to be listening before the CA calls back.
        if (!await WaitForApplicationStartedAsync(stoppingToken).ConfigureAwait(false))
            return;

        var failures = 0;
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TimeSpan wait;
                try
                {
                    wait = await CheckAsync(stoppingToken).ConfigureAwait(false);
                    failures = 0;
                }
                catch (Exception e) when (!stoppingToken.IsCancellationRequested)
                {
                    failures++;
                    wait = RenewalPlanner.GetRetryDelay(failures, (e as AcmeException)?.RetryAfter);
                    Log.RenewalFailed(logger, e, failures, wait);
                }

                await SleepAsync(wait, stoppingToken).ConfigureAwait(false);
            }
        }
        finally
        {
            await ReleaseLockAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Issues or renews if due. Returns how long to wait before the next check.</summary>
    internal async Task<TimeSpan> CheckAsync(CancellationToken cancellationToken)
    {
        await TrySaveAsync().ConfigureAwait(false);
        await LoadStoredAsync(startup: false, cancellationToken).ConfigureAwait(false);

        var current = selector.Current;
        string? replaces = null;

        if (!current.IsFallback && current.Covers(Options.Domains))
        {
            replaces = CertificateFactory.GetRenewalId(current.Leaf);
            var (window, retryAfter) = await GetRenewalWindowAsync(replaces, cancellationToken).ConfigureAwait(false);

            var now = time.GetUtcNow();
            var renewAt = RenewalPlanner.GetRenewalTime(current.NotBefore, current.NotAfter, window, Options.RenewBefore, _windowPosition);
            if (renewAt > now)
            {
                await ReleaseLockAsync().ConfigureAwait(false);
                var wait = RenewalPlanner.GetWaitTime(now, renewAt, retryAfter);
                Log.RenewalScheduled(logger, renewAt, wait);
                return wait;
            }
        }

        if (_lock is null)
        {
            _lock = await renewalLock.TryAcquireAsync(issuer.CertificateKey, cancellationToken).ConfigureAwait(false);
            if (_lock is null)
            {
                Log.RenewalLocked(logger, LockedRetry);
                return LockedRetry;
            }

            // The previous holder may have stored a certificate since we looked: check again before ordering.
            if (await LoadStoredAsync(startup: false, cancellationToken).ConfigureAwait(false))
                return TimeSpan.Zero;
        }

        var started = time.GetTimestamp();
        var lost = (_lock as ILosableLock)?.Lost ?? CancellationToken.None;
        using var orderCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lost);
        CertificateBundle issued;
        try
        {
            issued = await issuer.IssueAsync(replaces, orderCancellation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (lost.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            // Another instance may hold the lock now: leave the order to it and pick up what it stores.
            metrics.RecordIssuance(success: false, time.GetElapsedTime(started));
            await ReleaseLockAsync().ConfigureAwait(false);
            return LockedRetry;
        }
        catch
        {
            metrics.RecordIssuance(success: false, time.GetElapsedTime(started));
            throw;
        }

        var duration = time.GetElapsedTime(started);
        metrics.RecordIssuance(success: true, duration);
        Log.Issued(logger, string.Join(", ", issued.DnsNames), issued.NotAfter, duration);

        // Save before serving, so a shutdown right after issuance can't lose the certificate and cost another
        // order (and rate limit) on the next start. A failing store must not keep it from being served, though.
        _unsaved = issued;
        await TrySaveAsync().ConfigureAwait(false);

        selector.Use(issued);
        _windowPosition = Random.Shared.NextDouble();
        await ReleaseLockAsync().ConfigureAwait(false);
        return TimeSpan.Zero;
    }

    private async Task ReleaseLockAsync()
    {
        if (Interlocked.Exchange(ref _lock, null) is not { } held)
            return;
        try
        {
            await held.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception e)
        {
            // A lock that expires frees itself; one that doesn't is released when the process exits.
            Log.LockReleaseFailed(logger, e);
        }
    }

    /// <summary>Writes the last issued certificate to the store, if it isn't there yet.</summary>
    private async Task TrySaveAsync()
    {
        if (_unsaved is not { } certificate)
            return;

        try
        {
            // Not tied to shutdown: abandoning the write when the app stops is exactly what must not happen.
            // Bounded instead, so a hanging custom store can't block shutdown forever.
            using var timeout = new CancellationTokenSource(SaveTimeout, time);
            await store.WriteAsync(issuer.CertificateKey, CertificateFactory.ToPfx(certificate), timeout.Token)
                .ConfigureAwait(false);
            _unsaved = null;
        }
        catch (Exception e)
        {
            Log.StoreWriteFailed(logger, e);
        }
    }

    private async Task<(RenewalWindow? Window, TimeSpan? RetryAfter)> GetRenewalWindowAsync(
        string? certificateId, CancellationToken cancellationToken)
    {
        if (Options.RenewBefore is not null || certificateId is null)
            return (null, null);

        try
        {
            var client = await issuer.GetClientAsync(cancellationToken).ConfigureAwait(false);
            var info = await client.GetRenewalInfoAsync(certificateId, cancellationToken).ConfigureAwait(false);
            return (info?.Value.SuggestedWindow, info?.RetryAfter);
        }
        catch (Exception e) when (e is AcmeException or HttpRequestException)
        {
            // ARI is advisory: without it, fall back to renewing at one third of the lifetime.
            Log.RenewalInfoUnavailable(logger, e.Message);
            return (null, null);
        }
    }

    private async Task<bool> WaitForApplicationStartedAsync(CancellationToken stoppingToken)
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var onStarted = lifetime.ApplicationStarted.Register(() => started.TrySetResult());
        using var onStopping = stoppingToken.Register(() => started.TrySetCanceled(stoppingToken));
        try
        {
            await started.Task.ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private async Task SleepAsync(TimeSpan wait, CancellationToken stoppingToken)
    {
        if (wait <= TimeSpan.Zero)
            return;

        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var delay = Task.Delay(wait, time, cancel.Token);
        var wake = _wake.WaitAsync(cancel.Token);
        await Task.WhenAny(delay, wake).ConfigureAwait(false);
        await cancel.CancelAsync().ConfigureAwait(false);
    }

    public Task StartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
