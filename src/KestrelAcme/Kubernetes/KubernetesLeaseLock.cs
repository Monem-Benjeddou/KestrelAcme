using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using KestrelAcme.Storage;
using Microsoft.Extensions.Logging;

namespace KestrelAcme.Kubernetes;

/// <summary>
/// A <c>coordination.k8s.io</c> Lease per lock, as Kubernetes controllers use for leader election. The holder renews it
/// in the background; if the holder disappears, another replica takes it over once it has expired.
/// </summary>
internal sealed class KubernetesLeaseLock(KubernetesApi api, TimeProvider time, ILogger<KubernetesLeaseLock> logger) : IAcmeLock
{
    private readonly KubernetesApi _api = api;
    private readonly TimeProvider _time = time;
    private readonly ILogger _logger = logger;

    internal static readonly TimeSpan LeaseDuration = TimeSpan.FromSeconds(60);
    internal static readonly TimeSpan RenewInterval = LeaseDuration / 3;

    /// <summary>
    /// A holder that hasn't renewed for this long gives up, before the others can take over (LeaseDuration after they
    /// last saw a change), so two replicas never order at once even when the holder is cut off from the API server.
    /// </summary>
    internal static readonly TimeSpan RenewDeadline = LeaseDuration * 2 / 3;
    private static readonly TimeSpan ReleaseTimeout = TimeSpan.FromSeconds(10);

    // The pod name, plus a part of our own: a restarted pod keeps its name but must not inherit its predecessor's lease.
    private readonly string _identity = $"{Environment.MachineName}_{Guid.NewGuid():N}";

    // When each lease held by someone else was last seen to change. It counts as expired once it hasn't changed for its
    // duration by our own clock, so clocks that differ between nodes don't matter (client-go does the same).
    private readonly ConcurrentDictionary<string, (string? Version, long SeenAt)> _seen = new();

    public async Task<IAsyncDisposable?> TryAcquireAsync(string name, CancellationToken cancellationToken)
    {
        var leaseName = _api.ObjectName("lock", name);
        var path = $"{_api.LeasesPath}/{leaseName}";

        var (status, lease) = await _api.SendAsync(HttpMethod.Get, path, null, cancellationToken).ConfigureAwait(false);
        if (status == HttpStatusCode.NotFound)
        {
            lease = new JsonObject
            {
                ["apiVersion"] = "coordination.k8s.io/v1",
                ["kind"] = "Lease",
                ["metadata"] = new JsonObject
                {
                    ["name"] = leaseName,
                    ["labels"] = new JsonObject { ["app.kubernetes.io/managed-by"] = "kestrelacme" },
                    ["annotations"] = new JsonObject { ["kestrelacme/lock"] = name },
                },
            };
            Claim(lease, transitions: 0);
            (status, lease) = await _api.SendAsync(HttpMethod.Post, _api.LeasesPath, lease, cancellationToken).ConfigureAwait(false);
            return status == HttpStatusCode.Conflict ? null : new Held(this, path, lease!); // 409: another replica created it first
        }

        var spec = lease!["spec"];
        var holder = spec?["holderIdentity"]?.GetValue<string>();
        if (!string.IsNullOrEmpty(holder) && holder != _identity)
        {
            var version = lease["metadata"]?["resourceVersion"]?.GetValue<string>();
            var now = _time.GetTimestamp();
            var seen = _seen.AddOrUpdate(leaseName, (version, now), (_, previous) => previous.Version == version ? previous : (version, now));
            var duration = TimeSpan.FromSeconds(spec?["leaseDurationSeconds"]?.GetValue<int>() ?? (int)LeaseDuration.TotalSeconds);
            if (_time.GetElapsedTime(seen.SeenAt) < duration)
                return null;
        }

        // The resourceVersion read above goes back with the update: if anyone changed the lease since, it fails with 409.
        Claim(lease, transitions: (spec?["leaseTransitions"]?.GetValue<int>() ?? 0) + (holder == _identity ? 0 : 1));
        (status, lease) = await _api.SendAsync(HttpMethod.Put, path, lease, cancellationToken).ConfigureAwait(false);
        return status is HttpStatusCode.Conflict or HttpStatusCode.NotFound ? null : new Held(this, path, lease!);
    }

    private void Claim(JsonNode lease, int transitions)
    {
        var now = MicroTime(_time.GetUtcNow());
        lease["spec"] = new JsonObject
        {
            ["holderIdentity"] = _identity,
            ["leaseDurationSeconds"] = (int)LeaseDuration.TotalSeconds,
            ["acquireTime"] = now,
            ["renewTime"] = now,
            ["leaseTransitions"] = transitions,
        };
    }

    internal static string MicroTime(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);

    /// <summary>A held lease: renewed until disposed, then released so the next replica doesn't wait for it to expire.</summary>
    private sealed class Held : IAsyncDisposable, ILosableLock
    {
        private readonly KubernetesLeaseLock _owner;
        private readonly string _path;
        private readonly CancellationTokenSource _stop = new();
        private readonly CancellationTokenSource _lost = new();
        private readonly Task _renewing;
        private JsonNode _lease;
        private long _renewedAt;

        public Held(KubernetesLeaseLock owner, string path, JsonNode lease)
        {
            _owner = owner;
            _path = path;
            _lease = lease;
            _renewedAt = owner._time.GetTimestamp();
            _renewing = RenewAsync();
        }

        public CancellationToken Lost => _lost.Token;

        private async Task RenewAsync()
        {
            while (true)
            {
                try
                {
                    await Task.Delay(RenewInterval, _owner._time, _stop.Token).ConfigureAwait(false);
                    _lease["spec"]!["renewTime"] = MicroTime(_owner._time.GetUtcNow());
                    var (status, lease) = await _owner._api.SendAsync(HttpMethod.Put, _path, _lease, _stop.Token).ConfigureAwait(false);
                    if (status is HttpStatusCode.Conflict or HttpStatusCode.NotFound)
                    {
                        await GiveUpAsync().ConfigureAwait(false); // changed or deleted by someone else
                        return;
                    }
                    _lease = lease!;
                    _renewedAt = _owner._time.GetTimestamp();
                }
                catch (OperationCanceledException) when (_stop.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception e)
                {
                    Log.LeaseRenewalFailed(_owner._logger, _path, e);
                    if (_owner._time.GetElapsedTime(_renewedAt) >= RenewDeadline)
                    {
                        await GiveUpAsync().ConfigureAwait(false);
                        return;
                    }
                }
            }
        }

        private Task GiveUpAsync()
        {
            Log.LeaseLost(_owner._logger, _path);
            return _lost.CancelAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync().ConfigureAwait(false);
            await _renewing.ConfigureAwait(false);
            _stop.Dispose(); // not _lost: an order may still be linked to it

            _lease["spec"]!["holderIdentity"] = null;
            _lease["spec"]!["leaseDurationSeconds"] = 1;
            try
            {
                using var timeout = new CancellationTokenSource(ReleaseTimeout, _owner._time);
                await _owner._api.SendAsync(HttpMethod.Put, _path, _lease, timeout.Token).ConfigureAwait(false); // 409 if lost: fine
            }
            catch (Exception e)
            {
                Log.LockReleaseFailed(_owner._logger, e); // it expires on its own
            }
        }
    }
}
