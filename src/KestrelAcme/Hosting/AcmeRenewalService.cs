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
internal sealed class AcmeRenewalService(
    AcmeCertificateIssuer issuer,
    IAcmeStore store,
    CertificateSelector selector,
    AcmeMetrics metrics,
    IHostApplicationLifetime lifetime,
    IOptions<AcmeOptions> options,
    TimeProvider time,
    ILogger<AcmeRenewalService> logger) : BackgroundService, IHostedLifecycleService
{
    private static readonly TimeSpan SaveTimeout = TimeSpan.FromSeconds(30);

    private readonly SemaphoreSlim _wake = new(0, 1);

    // Picked once per certificate, so the moment inside the CA's window doesn't move every time we look.
    private double _windowPosition = Random.Shared.NextDouble();

    // An issued certificate the store failed to save; saving is retried on every check.
    private CertificateBundle? _unsaved;

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
    public async Task StartingAsync(CancellationToken cancellationToken)
    {
        try
        {
            var pfx = await store.ReadAsync(issuer.CertificateKey, cancellationToken).ConfigureAwait(false);
            if (pfx is null)
            {
                Log.NoStoredCertificate(logger);
                return;
            }

            var certificate = CertificateFactory.FromPfx(pfx);
            if (!certificate.Covers(Options.Domains))
                Log.StoredCertificateIgnored(logger, "it covers other domains");
            else if (certificate.NotAfter <= time.GetUtcNow())
                Log.StoredCertificateIgnored(logger, "it has expired");
            else
            {
                selector.Use(certificate);
                Log.LoadedCertificate(logger, string.Join(", ", certificate.DnsNames), certificate.NotAfter);
            }
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Log.StoredCertificateUnreadable(logger, e);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // HTTP-01 and TLS-ALPN-01 need Kestrel to be listening before the CA calls back.
        if (!await WaitForApplicationStartedAsync(stoppingToken).ConfigureAwait(false))
            return;

        var failures = 0;
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

    /// <summary>Issues or renews if due. Returns how long to wait before the next check.</summary>
    internal async Task<TimeSpan> CheckAsync(CancellationToken cancellationToken)
    {
        await TrySaveAsync().ConfigureAwait(false);

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
                var wait = RenewalPlanner.GetWaitTime(now, renewAt, retryAfter);
                Log.RenewalScheduled(logger, renewAt, wait);
                return wait;
            }
        }

        var started = time.GetTimestamp();
        CertificateBundle issued;
        try
        {
            issued = await issuer.IssueAsync(replaces, cancellationToken).ConfigureAwait(false);
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
        return TimeSpan.Zero;
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
