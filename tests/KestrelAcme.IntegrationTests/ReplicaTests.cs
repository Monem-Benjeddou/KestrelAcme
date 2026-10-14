using KestrelAcme.Hosting;
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
        PebbleDnsProvider dnsA = new(), dnsB = new();
        var startA = TestApp.StartAsync(pebble, output, "replicas.kestrelacme.test", _storage, Dns01Only,
            services => services.AddSingleton<IDnsChallengeProvider>(dnsA));
        var startB = TestApp.StartAsync(pebble, output, "replicas.kestrelacme.test", _storage, Dns01Only,
            services => services.AddSingleton<IDnsChallengeProvider>(dnsB), OtherHttpPort, OtherTlsPort);
        await using var a = await startA;
        await using var b = await startB;

        var issuedA = await a.WaitForCertificateAsync();
        var issuedB = await b.WaitForCertificateAsync();

        Assert.Equal(1, dnsA.Added.Count + dnsB.Added.Count); // one order in total
        Assert.Equal(issuedA.Leaf.Thumbprint, issuedB.Leaf.Thumbprint);
    }

    [PebbleFact]
    public async Task Http01_challenges_are_answered_by_the_replica_that_receives_them()
    {
        await using var a = await TestApp.StartAsync(pebble, output, "a.replicas.kestrelacme.test", _storage,
            o => o.Challenges = AcmeChallengeTypes.Http01);
        await using var b = await TestApp.StartAsync(pebble, output, "b.replicas.kestrelacme.test", _storage,
            o => o.Challenges = AcmeChallengeTypes.Http01, httpPort: OtherHttpPort, tlsPort: OtherTlsPort);

        await b.WaitForCertificateAsync(); // validated through A
        await a.WaitForCertificateAsync(); // A's own order done too, before checking that the answers were removed
        Assert.Empty(Directory.GetFiles(Path.Combine(_storage, "challenges"), "*", SearchOption.AllDirectories));
    }

    [PebbleFact]
    public async Task Tls_alpn01_challenges_are_answered_by_the_replica_that_receives_them()
    {
        await using var a = await TestApp.StartAsync(pebble, output, "a.replicas.kestrelacme.test", _storage,
            o => o.Challenges = AcmeChallengeTypes.TlsAlpn01);
        await using var b = await TestApp.StartAsync(pebble, output, "b.replicas.kestrelacme.test", _storage,
            o => o.Challenges = AcmeChallengeTypes.TlsAlpn01, httpPort: OtherHttpPort, tlsPort: OtherTlsPort);

        await b.WaitForCertificateAsync(); // validated through A
        await a.WaitForCertificateAsync(); // A's own order done too, before checking that the answers were removed
        Assert.Empty(Directory.GetFiles(Path.Combine(_storage, "challenges"), "*", SearchOption.AllDirectories));
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

    /// <summary>Counts order attempts, from the issuer's "Ordering a certificate" log entries.</summary>
    private sealed class OrderCounter : ILoggerProvider, ILogger
    {
        private int _count;

        public int Count => _count;

        public ILogger CreateLogger(string categoryName) => categoryName.EndsWith(".AcmeCertificateIssuer", StringComparison.Ordinal)
            ? this
            : NullLogger.Instance;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (eventId.Id == 6) // Log.Ordering
                Interlocked.Increment(ref _count);
        }

        public void Dispose()
        {
        }
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
