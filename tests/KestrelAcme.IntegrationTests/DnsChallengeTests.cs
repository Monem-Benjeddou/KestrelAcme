using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace KestrelAcme.IntegrationTests;

[Collection(PebbleCollection.Name)]
public sealed class DnsChallengeTests(PebbleFixture pebble, ITestOutputHelper output) : IDisposable
{
    private readonly string _storage = Directory.CreateTempSubdirectory("kestrelacme-").FullName;
    private readonly PebbleDnsProvider _dns = new();

    [PebbleFact]
    public async Task Issues_a_wildcard_certificate_together_with_the_plain_name()
    {
        await using var app = await TestApp.StartAsync(pebble, output, "wild.kestrelacme.test", _storage, o =>
        {
            o.Domains.Add("*.wild.kestrelacme.test");
            o.DnsPropagationDelay = TimeSpan.Zero;
        }, services => services.AddSingleton<IDnsChallengeProvider>(_dns));

        var issued = await app.WaitForCertificateAsync();

        Assert.Equal(["wild.kestrelacme.test", "*.wild.kestrelacme.test"], issued.DnsNames);
        Assert.Contains("_acme-challenge.wild.kestrelacme.test", _dns.Added);

        // Any single label under the wildcard gets it.
        var (leaf, _, _) = await TestApp.HandshakeAsync("api.wild.kestrelacme.test");
        Assert.Equal(issued.Leaf.Thumbprint, leaf.Thumbprint);

        Assert.Empty(_dns.Live); // every record cleaned up
    }

    [PebbleFact]
    public async Task Issues_with_dns01_alone()
    {
        await using var app = await TestApp.StartAsync(pebble, output, "dnsonly.kestrelacme.test", _storage, o =>
        {
            o.Challenges = AcmeChallengeTypes.Dns01;
            o.DnsPropagationDelay = TimeSpan.Zero;
        }, services => services.AddSingleton<IDnsChallengeProvider>(_dns));

        var issued = await app.WaitForCertificateAsync();

        Assert.Equal(["dnsonly.kestrelacme.test"], issued.DnsNames);
        Assert.Equal(["_acme-challenge.dnsonly.kestrelacme.test"], _dns.Added);
        Assert.Empty(_dns.Live);
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
