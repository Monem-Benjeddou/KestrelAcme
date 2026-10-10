using Xunit.Abstractions;

namespace KestrelAcme.IntegrationTests;

[Collection(PebbleCollection.Name)]
public sealed class IssuanceTests(PebbleFixture pebble, ITestOutputHelper output) : IDisposable
{
    private readonly string _storage = Directory.CreateTempSubdirectory("kestrelacme-").FullName;

    [PebbleFact]
    public async Task Issues_with_http01_and_serves_the_certificate_with_its_chain()
    {
        await using var app = await TestApp.StartAsync(pebble, output, "http01.kestrelacme.test", _storage,
            o => o.Challenges = AcmeChallengeTypes.Http01);

        var issued = await app.WaitForCertificateAsync();
        var (leaf, chain, protocol) = await TestApp.HandshakeAsync("http01.kestrelacme.test");

        Assert.Equal(issued.Leaf.Thumbprint, leaf.Thumbprint);
        Assert.Equal(["http01.kestrelacme.test"], issued.DnsNames);
        Assert.Equal("http/1.1", protocol);

        // The intermediate came from the server: it's in no local store, yet the client could chain to it.
        Assert.True(chain.Count >= 2, "the server should send the intermediate certificate");
        Assert.Equal(leaf.Issuer, chain[1].Subject);
    }

    [PebbleFact]
    public async Task Issues_with_tls_alpn01_alone()
    {
        await using var app = await TestApp.StartAsync(pebble, output, "alpn.kestrelacme.test", _storage,
            o => o.Challenges = AcmeChallengeTypes.TlsAlpn01);

        var issued = await app.WaitForCertificateAsync();
        var (leaf, _, _) = await TestApp.HandshakeAsync("alpn.kestrelacme.test");

        Assert.Equal(issued.Leaf.Thumbprint, leaf.Thumbprint);

        var root = await pebble.GetIssuingRootAsync();
        using var chain = new System.Security.Cryptography.X509Certificates.X509Chain();
        chain.ChainPolicy.TrustMode = System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.ExtraStore.AddRange(issued.Intermediates);
        chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
        Assert.True(chain.Build(leaf), "the certificate should chain to Pebble's root");
    }

    [PebbleFact]
    public async Task Restart_reuses_the_stored_certificate_from_the_first_handshake()
    {
        string thumbprint;
        await using (var first = await TestApp.StartAsync(pebble, output, "restart.kestrelacme.test", _storage))
            thumbprint = (await first.WaitForCertificateAsync()).Leaf.Thumbprint;

        await using var second = await TestApp.StartAsync(pebble, output, "restart.kestrelacme.test", _storage);

        Assert.False(second.Selector.Current.IsFallback);
        Assert.Equal(thumbprint, second.Selector.Current.Leaf.Thumbprint);
        var (leaf, _, _) = await TestApp.HandshakeAsync("restart.kestrelacme.test");
        Assert.Equal(thumbprint, leaf.Thumbprint);
    }

    [PebbleFact]
    public async Task Renews_without_restart_when_the_ca_says_so()
    {
        await using var app = await TestApp.StartAsync(pebble, output, "renew.kestrelacme.test", _storage);
        var first = await app.WaitForCertificateAsync();

        // Ask Pebble's ARI to report the renewal window as already open, then nudge the service.
        var now = DateTimeOffset.UtcNow;
        await pebble.SetRenewalInfoAsync(first.Leaf, now.AddHours(-2), now.AddHours(-1));
        app.Renewal.RequestCheck();

        var renewed = await app.WaitForCertificateAsync(first.Leaf.Thumbprint);
        var (leaf, _, _) = await TestApp.HandshakeAsync("renew.kestrelacme.test");

        Assert.Equal(renewed.Leaf.Thumbprint, leaf.Thumbprint);
        Assert.NotEqual(first.Leaf.SerialNumber, renewed.Leaf.SerialNumber);
    }

    [PebbleFact]
    public async Task Plain_http_requests_still_reach_the_app()
    {
        await using var app = await TestApp.StartAsync(pebble, output, "plain.kestrelacme.test", _storage);
        using var http = new HttpClient();

        var body = await http.GetStringAsync($"http://127.0.0.1:{PebbleFixture.HttpPort}/");

        Assert.Equal("hello over https", body);
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
