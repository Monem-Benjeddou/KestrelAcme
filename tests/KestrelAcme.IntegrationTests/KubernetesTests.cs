using KestrelAcme.Kubernetes;
using KestrelAcme.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit.Abstractions;

namespace KestrelAcme.IntegrationTests;

/// <summary>
/// Runs against a real API server. <c>KESTRELACME_KUBERNETES</c> names a folder laid out like a pod's service account
/// (<c>token</c>, <c>ca.crt</c>, <c>namespace</c>) plus <c>server</c>, the API server URL. See eng/kind.sh.
/// </summary>
[Collection(PebbleCollection.Name)]
public sealed class KubernetesTests(PebbleFixture pebble, ITestOutputHelper output)
{
    private static readonly string? Folder = Environment.GetEnvironmentVariable("KESTRELACME_KUBERNETES");

    // Each test gets its own objects, so runs don't see each other's.
    private readonly string _name = "test-" + Guid.NewGuid().ToString("N")[..8];

    [KubernetesFact]
    public async Task Secrets_store_values_and_delete_them()
    {
        var store = new KubernetesSecretStore(CreateApi());

        Assert.Null(await store.ReadAsync("certificates/ca/example.com.pfx", default));
        await store.WriteAsync("certificates/ca/example.com.pfx", [1, 2, 3], default);
        await store.WriteAsync("certificates/ca/example.com.pfx", [4, 5], default);
        Assert.Equal([4, 5], await store.ReadAsync("certificates/ca/example.com.pfx", default));

        await store.DeleteAsync("certificates/ca/example.com.pfx", default);
        await store.DeleteAsync("certificates/ca/example.com.pfx", default);
        Assert.Null(await store.ReadAsync("certificates/ca/example.com.pfx", default));
    }

    [KubernetesFact]
    public async Task A_lease_has_one_holder_and_is_released_on_dispose()
    {
        var first = CreateLock(TimeProvider.System);
        var second = CreateLock(TimeProvider.System);

        var held = await first.TryAcquireAsync("certificates/ca/example.com.pfx", default);
        Assert.NotNull(held);
        Assert.Null(await second.TryAcquireAsync("certificates/ca/example.com.pfx", default));

        await held!.DisposeAsync();
        await using var taken = await second.TryAcquireAsync("certificates/ca/example.com.pfx", default);
        Assert.NotNull(taken);
    }

    [KubernetesFact]
    public async Task An_abandoned_lease_is_taken_over_once_it_has_expired_by_the_observers_clock()
    {
        var crashed = new ManualTime(); // never renews, like a holder that died
        var observer = new ManualTime();
        var held = await CreateLock(crashed).TryAcquireAsync("certificates/ca/example.com.pfx", default);
        var other = CreateLock(observer);

        Assert.Null(await other.TryAcquireAsync("certificates/ca/example.com.pfx", default));
        observer.Advance(KubernetesLeaseLock.LeaseDuration - TimeSpan.FromSeconds(1));
        Assert.Null(await other.TryAcquireAsync("certificates/ca/example.com.pfx", default));
        observer.Advance(TimeSpan.FromSeconds(2));
        await using var taken = await other.TryAcquireAsync("certificates/ca/example.com.pfx", default);
        Assert.NotNull(taken);

        await held!.DisposeAsync(); // its release is refused (409) and ignored
    }

    [KubernetesFact]
    public async Task A_holder_whose_lease_was_taken_over_notices_at_its_next_renewal()
    {
        var api = CreateApi();
        var held = (IAcmeLockHandle)(await CreateLock(TimeProvider.System).TryAcquireAsync("certificates/ca/example.com.pfx", default))!;

        // Another replica takes it over (the README's Role can't delete leases, only update them).
        var path = $"{api.LeasesPath}/{api.ObjectName("lock", "certificates/ca/example.com.pfx")}";
        var (_, lease) = await api.SendAsync(HttpMethod.Get, path, null, default);
        lease!["spec"]!["holderIdentity"] = "someone-else";
        await api.SendAsync(HttpMethod.Put, path, lease, default);

        await Task.Delay(KubernetesLeaseLock.RenewInterval + TimeSpan.FromSeconds(5));
        Assert.True(held.Lost.IsCancellationRequested);
        await held.DisposeAsync();
    }

    [KubernetesFact]
    public async Task A_holder_cut_off_from_the_api_server_gives_up_before_anyone_can_take_over()
    {
        var partition = new Partition();
        var held = (IAcmeLockHandle)(await CreateLock(TimeProvider.System, partition).TryAcquireAsync("certificates/ca/example.com.pfx", default))!;
        var started = DateTime.UtcNow;
        partition.Cut = true;

        var lost = new TaskCompletionSource();
        await using var registration = held.Lost.Register(lost.SetResult);
        await lost.Task.WaitAsync(KubernetesLeaseLock.LeaseDuration);

        // The last change anyone saw is the acquisition, just before the cut: others can take over LeaseDuration after
        // it. The holder must have given up well before.
        Assert.InRange(DateTime.UtcNow - started, KubernetesLeaseLock.RenewDeadline - TimeSpan.FromSeconds(1),
            KubernetesLeaseLock.LeaseDuration - TimeSpan.FromSeconds(10));
        await held.DisposeAsync();
    }

    [KubernetesFact]
    public async Task A_renewal_that_hangs_doesnt_keep_the_holder_past_its_deadline()
    {
        // Packets dropped rather than refused: requests hang instead of failing.
        var partition = new Partition();
        var held = (IAcmeLockHandle)(await CreateLock(TimeProvider.System, partition).TryAcquireAsync("certificates/ca/example.com.pfx", default))!;
        var started = DateTime.UtcNow;
        partition.Hang = true;

        var lost = new TaskCompletionSource();
        await using var registration = held.Lost.Register(lost.SetResult);
        await lost.Task.WaitAsync(KubernetesLeaseLock.LeaseDuration);

        Assert.InRange(DateTime.UtcNow - started, KubernetesLeaseLock.RenewDeadline - TimeSpan.FromSeconds(1),
            KubernetesLeaseLock.LeaseDuration - TimeSpan.FromSeconds(10));
        await held.DisposeAsync();
    }

    [KubernetesFact]
    public async Task An_order_in_progress_is_abandoned_when_the_lease_is_lost()
    {
        var partition = new Partition();
        var dns = new StuckDnsProvider();
        await using var app = await TestApp.StartAsync(pebble, output, "lost.k8s.kestrelacme.test", Directory.CreateTempSubdirectory().FullName,
            o =>
            {
                Dns01Only(o);
                o.IssuanceTimeout = TimeSpan.FromMinutes(5); // so only the lost lease can stop the order in time
            },
            services => services.AddSingleton<IDnsChallengeProvider>(dns).AddKestrelAcmeKubernetes(Configure)
                .AddHttpClient(KubernetesAcmeServiceCollectionExtensions.HttpClientName).AddHttpMessageHandler(() => partition));

        await dns.Started.Task.WaitAsync(TimeSpan.FromSeconds(30)); // ordering, under the lease
        partition.Cut = true;

        await dns.Cancelled.Task.WaitAsync(KubernetesLeaseLock.LeaseDuration);
        Assert.True(app.Selector.Current.IsFallback);
    }

    [KubernetesFact]
    public async Task Replicas_without_a_shared_volume_order_once_and_serve_the_same_certificate()
    {
        var orders = new OrderCounter();
        var startA = TestApp.StartAsync(pebble, output, "k8s.kestrelacme.test", Directory.CreateTempSubdirectory().FullName, Dns01Only,
            services => services.AddSingleton<IDnsChallengeProvider>(new PebbleDnsProvider()).AddSingleton<ILoggerProvider>(orders)
                .AddKestrelAcmeKubernetes(Configure));
        var startB = TestApp.StartAsync(pebble, output, "k8s.kestrelacme.test", Directory.CreateTempSubdirectory().FullName, Dns01Only,
            services => services.AddSingleton<IDnsChallengeProvider>(new PebbleDnsProvider()).AddSingleton<ILoggerProvider>(orders)
                .AddKestrelAcmeKubernetes(Configure), 5102, 5101);
        await using var a = await startA;
        await using var b = await startB;

        var issuedA = await a.WaitForCertificateAsync();
        var issuedB = await b.WaitForCertificateAsync();

        Assert.Equal(1, orders.Count);
        Assert.Equal(issuedA.Leaf.Thumbprint, issuedB.Leaf.Thumbprint);
    }

    [KubernetesFact]
    public async Task Challenges_are_answered_from_secrets_by_a_replica_that_isnt_ordering()
    {
        var orders = new OrderCounter();

        // B orders, listening where Pebble doesn't validate; A starts meanwhile where it does, and answers for B.
        await using var b = await TestApp.StartAsync(pebble, output, "shared.k8s.kestrelacme.test", Directory.CreateTempSubdirectory().FullName,
            o => o.Challenges = AcmeChallengeTypes.Http01,
            services => services.AddSingleton<ILoggerProvider>(orders).AddKestrelAcmeKubernetes(Configure), 5102, 5101);
        await orders.FirstOrder.WaitAsync(TimeSpan.FromSeconds(10));
        await using var a = await TestApp.StartAsync(pebble, output, "shared.k8s.kestrelacme.test", Directory.CreateTempSubdirectory().FullName,
            o => o.Challenges = AcmeChallengeTypes.Http01,
            services => services.AddSingleton<ILoggerProvider>(orders).AddKestrelAcmeKubernetes(Configure));

        var issued = await b.WaitForCertificateAsync();
        Assert.Equal(issued.Leaf.Thumbprint, (await a.WaitForCertificateAsync()).Leaf.Thumbprint);
        Assert.Equal(1, orders.Count);
    }

    private static void Dns01Only(AcmeOptions o)
    {
        o.Challenges = AcmeChallengeTypes.Dns01;
        o.DnsPropagationDelay = TimeSpan.Zero;
    }

    private void Configure(KubernetesAcmeOptions o)
    {
        o.Name = _name;
        o.ApiServer = new Uri(File.ReadAllText(Path.Combine(Folder!, "server")).Trim());
        o.TokenPath = Path.Combine(Folder!, "token");
        o.CertificateAuthorityPath = Path.Combine(Folder!, "ca.crt");
    }

    private KubernetesApi CreateApi(Partition? partition = null)
    {
        var services = new ServiceCollection();
        services.AddKestrelAcmeKubernetes(Configure);
        if (partition is not null)
            services.AddHttpClient(KubernetesAcmeServiceCollectionExtensions.HttpClientName).AddHttpMessageHandler(() => partition);
        var provider = services.BuildServiceProvider();
        return new KubernetesApi(provider.GetRequiredService<IHttpClientFactory>(), provider.GetRequiredService<IOptions<KubernetesAcmeOptions>>());
    }

    private KubernetesLeaseLock CreateLock(TimeProvider time, Partition? partition = null) =>
        new(CreateApi(partition), time, NullLogger<KubernetesLeaseLock>.Instance);

    /// <summary>A DNS host that never finishes creating the record, keeping the order in progress.</summary>
    private sealed class StuckDnsProvider : IDnsChallengeProvider
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Cancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task AddTxtRecordAsync(string name, string value, CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }
            finally
            {
                Cancelled.TrySetResult();
            }
        }

        public Task RemoveTxtRecordAsync(string name, string value, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    /// <summary>Fails every request once cut, like a network split between the pod and the API server.</summary>
    private sealed class Partition : DelegatingHandler
    {
        public volatile bool Cut;
        public volatile bool Hang;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Hang)
                await Task.Delay(Timeout.Infinite, cancellationToken);
            return Cut ? throw new HttpRequestException("Network unreachable (simulated).") : await base.SendAsync(request, cancellationToken);
        }
    }

    /// <summary>A clock that moves only when told to, and whose timers never fire.</summary>
    private sealed class ManualTime : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;

        public void Advance(TimeSpan by) => _now += by;

        public override DateTimeOffset GetUtcNow() => _now;

        public override long GetTimestamp() => _now.UtcTicks;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) => new NeverFires();

        private sealed class NeverFires : ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period) => true;

            public void Dispose()
            {
            }

            public ValueTask DisposeAsync() => default;
        }
    }

    private sealed class KubernetesFactAttribute : FactAttribute
    {
        public KubernetesFactAttribute()
        {
            if (string.IsNullOrEmpty(Folder))
                Skip = "No Kubernetes cluster configured. Run eng/kind.sh, then set KESTRELACME_KUBERNETES.";
            else if (PebbleFixture.PebbleRoot is null)
                Skip = "Pebble is not built. Run eng/pebble.sh (needs Go) or set PEBBLE_ROOT.";
        }
    }
}
