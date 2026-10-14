using KestrelAcme.Hosting;
using KestrelAcme.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit.Abstractions;

namespace KestrelAcme.IntegrationTests;

/// <summary>Instances sharing a storage folder, as replicas behind a load balancer would.</summary>
[Collection(PebbleCollection.Name)]
public sealed class ReplicaTests(PebbleFixture pebble, ITestOutputHelper output) : IDisposable
{
    // Pebble only validates on PebbleFixture.HttpPort and TlsPort: listening elsewhere, a replica never receives
    // the certificate authority's requests, like a pod the load balancer didn't pick.
    private const int OtherHttpPort = 5102;
    private const int OtherTlsPort = 5101;

    private readonly string _storage = Directory.CreateTempSubdirectory("kestrelacme-").FullName;

    [PebbleFact]
    public async Task Replicas_starting_together_order_once_and_serve_the_same_certificate()
    {
        // Counted from the logs: with a shared account, a second order could reuse the first one's authorization and
        // create no DNS record, so records don't tell.
        var orders = new OrderCounter();
        var startA = TestApp.StartAsync(pebble, output, "replicas.kestrelacme.test", _storage, Dns01Only,
            services => services.AddSingleton<IDnsChallengeProvider>(new PebbleDnsProvider()).AddSingleton<ILoggerProvider>(orders));
        var startB = TestApp.StartAsync(pebble, output, "replicas.kestrelacme.test", _storage, Dns01Only,
            services => services.AddSingleton<IDnsChallengeProvider>(new PebbleDnsProvider()).AddSingleton<ILoggerProvider>(orders),
            OtherHttpPort, OtherTlsPort);
        await using var a = await startA;
        await using var b = await startB;

        var issuedA = await a.WaitForCertificateAsync();
        var issuedB = await b.WaitForCertificateAsync();

        Assert.Equal(1, orders.Count);
        Assert.Equal(issuedA.Leaf.Thumbprint, issuedB.Leaf.Thumbprint);
    }

    [PebbleFact]
    public Task Http01_challenges_are_answered_by_a_replica_that_isnt_ordering() => AnsweredByAnotherReplicaAsync(AcmeChallengeTypes.Http01);

    [PebbleFact]
    public Task Tls_alpn01_challenges_are_answered_by_a_replica_that_isnt_ordering() => AnsweredByAnotherReplicaAsync(AcmeChallengeTypes.TlsAlpn01);

    private async Task AnsweredByAnotherReplicaAsync(AcmeChallengeTypes type)
    {
        var domain = $"{type}.shared.kestrelacme.test".ToLowerInvariant();
        var orders = new OrderCounter();

        // B orders, listening where Pebble doesn't validate.
        await using var b = await TestApp.StartAsync(pebble, output, domain, _storage, o => o.Challenges = type,
            services => services.AddSingleton<ILoggerProvider>(orders), OtherHttpPort, OtherTlsPort);
        await orders.FirstOrder.WaitAsync(TimeSpan.FromSeconds(10));

        // A starts while B's order runs, where Pebble validates: it answers B's challenges, then picks up B's certificate.
        await using var a = await TestApp.StartAsync(pebble, output, domain, _storage, o => o.Challenges = type,
            services => services.AddSingleton<ILoggerProvider>(orders));

        var issued = await b.WaitForCertificateAsync();
        Assert.Equal(issued.Leaf.Thumbprint, (await a.WaitForCertificateAsync()).Leaf.Thumbprint);
        Assert.Equal(1, orders.Count);
        Assert.Empty(Directory.GetFiles(Path.Combine(_storage, "challenges"), "*", SearchOption.AllDirectories));
    }

    [PebbleFact]
    public async Task The_lock_is_kept_until_the_certificate_is_stored()
    {
        // A's store takes everything but the certificate, so A can't hand it over.
        var orders = new OrderCounter();
        PebbleDnsProvider dnsA = new(), dnsB = new();
        await using var a = await TestApp.StartAsync(pebble, output, "unsaved.kestrelacme.test", _storage, Dns01Only, services => services
            .AddSingleton<ILoggerProvider>(orders).AddSingleton<IDnsChallengeProvider>(dnsA)
            .AddSingleton<IAcmeStore>(new FlakyStore(new FileSystemAcmeStore(_storage), failWrites: true))
            .AddSingleton<IAcmeLock>(new FileSystemAcmeLock(new FileSystemAcmeStore(_storage))));
        await a.WaitForCertificateAsync(); // issued and served, not stored

        await using var b = await TestApp.StartAsync(pebble, output, "unsaved.kestrelacme.test", _storage, Dns01Only,
            services => services.AddSingleton<ILoggerProvider>(orders).AddSingleton<IDnsChallengeProvider>(dnsB),
            OtherHttpPort, OtherTlsPort);
        await Task.Delay(AcmeRenewalService.LockedRetry + TimeSpan.FromSeconds(5));

        Assert.Equal(1, orders.Count); // B didn't order again while A still has to store it
    }

    [PebbleFact]
    public async Task A_store_that_cant_be_read_doesnt_lead_to_an_order()
    {
        var orders = new OrderCounter();
        await using var app = await TestApp.StartAsync(pebble, output, "unreadable.kestrelacme.test", _storage, Dns01Only, services => services
            .AddSingleton<ILoggerProvider>(orders).AddSingleton<IDnsChallengeProvider>(new PebbleDnsProvider())
            .AddSingleton<IAcmeStore>(new FlakyStore(new FileSystemAcmeStore(_storage), failReads: true))
            .AddSingleton<IAcmeLock>(new FileSystemAcmeLock(new FileSystemAcmeStore(_storage))));

        await Task.Delay(TimeSpan.FromSeconds(5));

        Assert.Equal(0, orders.Count); // backing off instead of taking the error for "no certificate"
    }

    /// <summary>A store whose certificate reads or writes fail, like an API server having a bad moment.</summary>
    private sealed class FlakyStore(IAcmeStore inner, bool failReads = false, bool failWrites = false) : IAcmeStore
    {
        public Task<byte[]?> ReadAsync(string key, CancellationToken cancellationToken) =>
            failReads && key.StartsWith("certificates/", StringComparison.Ordinal)
                ? throw new IOException("Store unavailable (simulated).")
                : inner.ReadAsync(key, cancellationToken);

        public Task WriteAsync(string key, byte[] value, CancellationToken cancellationToken) =>
            failWrites && key.StartsWith("certificates/", StringComparison.Ordinal)
                ? throw new IOException("Store unavailable (simulated).")
                : inner.WriteAsync(key, value, cancellationToken);

        public Task DeleteAsync(string key, CancellationToken cancellationToken) => inner.DeleteAsync(key, cancellationToken);
    }

    [PebbleFact]
    public async Task While_the_holder_backs_off_after_a_failure_the_other_replicas_dont_order()
    {
        // Neither replica receives the CA's requests, so every validation fails.
        var orders = new OrderCounter();
        await using var a = await TestApp.StartAsync(pebble, output, "failing.kestrelacme.test", _storage,
            o => o.Challenges = AcmeChallengeTypes.Http01, services => services.AddSingleton<ILoggerProvider>(orders),
            OtherHttpPort, OtherTlsPort);
        await using var b = await TestApp.StartAsync(pebble, output, "failing.kestrelacme.test", _storage,
            o => o.Challenges = AcmeChallengeTypes.Http01, services => services.AddSingleton<ILoggerProvider>(orders),
            OtherHttpPort + 100, OtherTlsPort + 100);

        // Past the moment the waiting replica looks again: it must find the lock still held.
        await Task.Delay(AcmeRenewalService.LockedRetry + TimeSpan.FromSeconds(5));

        Assert.Equal(1, orders.Count);
    }

    private static void Dns01Only(AcmeOptions o)
    {
        o.Challenges = AcmeChallengeTypes.Dns01;
        o.DnsPropagationDelay = TimeSpan.Zero;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_storage, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
