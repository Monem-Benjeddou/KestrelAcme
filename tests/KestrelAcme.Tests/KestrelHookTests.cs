using System.Net.Security;
using KestrelAcme.Certificates;
using KestrelAcme.Hosting;
using KestrelAcme.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace KestrelAcme.Tests;

public sealed class KestrelHookTests : IDisposable
{
    private const string SharedToken = "shared-token_0123456789abcdef";

    private readonly string _root = Directory.CreateTempSubdirectory("kestrelacme-hooks-").FullName;
    private readonly FileSystemAcmeStore _store;
    private readonly CertificateSelector _selector;
    private readonly ChallengeResponder _challenges;
    private readonly KestrelOptionsSetup _setup;

    public KestrelHookTests()
    {
        var options = Options.Create(new AcmeOptions());
        options.Value.Domains.Add("example.com");
        _store = new FileSystemAcmeStore(_root);
        _selector = new CertificateSelector(options, TimeProvider.System);
        _challenges = new ChallengeResponder(_store, new FileSystemAcmeLock(_store), options, TimeProvider.System, NullLogger<ChallengeResponder>.Instance);
        _setup = new KestrelOptionsSetup(_selector, _challenges, NullLogger<KestrelOptionsSetup>.Instance);
    }

    [Fact]
    public void Endpoint_on_the_placeholder_gets_the_current_certificate_and_its_chain()
    {
        var issued = CertificateFactory.CreateFallback(["example.com"], DateTimeOffset.UtcNow);
        _selector.Use(issued);
        var ssl = new SslServerAuthenticationOptions { ServerCertificate = _selector.Placeholder.Leaf };

        _setup.OnAuthenticate(Connection(new ClientHello("example.com", ["h2"])), ssl);

        Assert.Same(issued.Context, ssl.ServerCertificateContext);
        Assert.Null(ssl.ServerCertificate);
    }

    [Fact]
    public void Endpoint_with_its_own_certificate_is_left_alone()
    {
        var own = CertificateFactory.CreateFallback(["own.example"], DateTimeOffset.UtcNow);
        var ssl = new SslServerAuthenticationOptions { ServerCertificateContext = own.Context };

        _setup.OnAuthenticate(Connection(new ClientHello("own.example", [])), ssl);

        Assert.Same(own.Context, ssl.ServerCertificateContext);
    }

    [Fact]
    public void Tls_alpn_validation_gets_the_challenge_certificate_and_protocol()
    {
        var challenge = CertificateFactory.CreateTlsAlpnChallenge("example.com", "t.k", DateTimeOffset.UtcNow);
        _challenges.AddTlsAlpn01("example.com", challenge);
        var ssl = new SslServerAuthenticationOptions
        {
            ServerCertificate = _selector.Placeholder.Leaf,
            ApplicationProtocols = [SslApplicationProtocol.Http2],
        };

        _setup.OnAuthenticate(Connection(new ClientHello("example.com", ["acme-tls/1"])), ssl);

        Assert.Same(challenge.Context, ssl.ServerCertificateContext);
        Assert.Equal([new SslApplicationProtocol("acme-tls/1")], ssl.ApplicationProtocols);
    }

    [Fact]
    public async Task Tls_alpn_validation_of_another_instances_order_gets_the_shared_challenge_certificate()
    {
        await _challenges.PublishAsync([new SharedAnswer("tls-alpn-01", "example.com", "t.k")], default);
        using var shared = await _challenges.LoadSharedTlsAlpn01Async("EXAMPLE.com", default);
        var connection = Connection(new ClientHello("EXAMPLE.com", ["acme-tls/1"]));
        connection.Features.Set(new SharedTlsAlpn01Challenge(shared!));
        var ssl = new SslServerAuthenticationOptions { ServerCertificate = _selector.Placeholder.Leaf };

        _setup.OnAuthenticate(connection, ssl);

        Assert.Same(shared!.Context, ssl.ServerCertificateContext);
        Assert.Equal([new SslApplicationProtocol("acme-tls/1")], ssl.ApplicationProtocols);
    }

    [Theory]
    [InlineData("other.example.com")]
    [InlineData("../accounts")]
    [InlineData("*.example.com")]
    [InlineData("")]
    public async Task No_shared_tls_alpn_certificate_without_a_shared_answer_or_for_odd_names(string name)
    {
        await _challenges.PublishAsync([new SharedAnswer("tls-alpn-01", "example.com", "t.k")], default);
        Assert.Null(await _challenges.LoadSharedTlsAlpn01Async(name, default));
    }

    [Fact]
    public void Acme_protocol_without_a_pending_challenge_gets_the_normal_certificate()
    {
        var ssl = new SslServerAuthenticationOptions { ServerCertificate = _selector.Placeholder.Leaf };

        _setup.OnAuthenticate(Connection(new ClientHello("example.com", ["acme-tls/1"])), ssl);

        Assert.Same(_selector.Current.Context, ssl.ServerCertificateContext);
    }

    [Theory]
    [InlineData("GET", "/.well-known/acme-challenge/tok", 200, "tok.thumb")]
    [InlineData("HEAD", "/.well-known/acme-challenge/tok", 418, "")]
    [InlineData("GET", "/.well-known/acme-challenge/unknown", 418, "")]
    [InlineData("GET", "/.well-known/acme-challenge/", 418, "")]
    [InlineData("GET", "/other", 418, "")]
    [InlineData("GET", "/.well-known/acme-challenge/" + SharedToken, 200, "shared.thumb")] // another instance's order
    [InlineData("GET", "/.well-known/acme-challenge/..%2F..%2Faccounts", 418, "")]
    public async Task Http01_answers_known_tokens_and_passes_everything_else_on(string method, string path, int status, string body)
    {
        _challenges.AddHttp01("tok", "tok.thumb");
        await _challenges.PublishAsync([new SharedAnswer("http-01", SharedToken, "shared.thumb")], default);
        var app = new ApplicationBuilder(new ServiceCollection().BuildServiceProvider());
        new Http01ChallengeStartupFilter(_challenges, NullLogger<Http01ChallengeStartupFilter>.Instance).Configure(a => a.Run(c =>
        {
            c.Response.StatusCode = 418;
            return Task.CompletedTask;
        }))(app);
        var pipeline = app.Build();

        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        await pipeline(context);

        Assert.Equal(status, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        Assert.Equal(body, await new StreamReader(context.Response.Body).ReadToEndAsync());
    }

    [Fact]
    public async Task Lookups_for_made_up_tokens_read_the_store_at_most_once_per_interval()
    {
        var reads = new CountingStore(_store);
        var options = Options.Create(new AcmeOptions());
        options.Value.Domains.Add("example.com");
        var challenges = new ChallengeResponder(reads, new FileSystemAcmeLock(_store), options, TimeProvider.System, NullLogger<ChallengeResponder>.Instance);

        // A flood of requests for tokens nobody published.
        var flood = Enumerable.Range(0, 500).Select(i => challenges.FindHttp01Async($"made-up-token-{i:D10}-xxxxxxxx", default));
        Assert.All(await Task.WhenAll(flood), Assert.Null);
        Assert.Equal(1, reads.Reads);

        // A real answer published meanwhile is found once the interval has passed, as the issuer's PublishDelay ensures.
        await challenges.PublishAsync([new SharedAnswer("http-01", SharedToken, "shared.thumb")], default);
        await Task.Delay(ChallengeResponder.MinRefreshInterval);
        Assert.Equal("shared.thumb", await challenges.FindHttp01Async(SharedToken, default));
        Assert.Equal(2, reads.Reads);
    }

    [Fact]
    public async Task A_custom_store_without_a_lock_is_never_used_for_challenges()
    {
        var reads = new CountingStore(_store);
        var options = Options.Create(new AcmeOptions());
        options.Value.Domains.Add("example.com");
        var challenges = new ChallengeResponder(reads, new UncoordinatedAcmeLock(reads, NullLogger<UncoordinatedAcmeLock>.Instance),
            options, TimeProvider.System, NullLogger<ChallengeResponder>.Instance);

        Assert.False(challenges.Shares);
        Assert.Null(await challenges.FindHttp01Async(SharedToken, default));
        Assert.Null(await challenges.LoadSharedTlsAlpn01Async("example.com", default));
        Assert.Equal(0, reads.Reads);
    }

    private sealed class CountingStore(IAcmeStore inner) : IAcmeStore
    {
        private int _reads;

        public int Reads => _reads;

        public Task<byte[]?> ReadAsync(string key, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _reads);
            return inner.ReadAsync(key, cancellationToken);
        }

        public Task WriteAsync(string key, byte[] value, CancellationToken cancellationToken) => inner.WriteAsync(key, value, cancellationToken);
    }

    [Theory]
    [InlineData("abcdefghijklmnopqrstuvwxyz_-0123456789", true)]
    [InlineData("short", false)]
    [InlineData("..%2F..%2Faccounts%2Fca%2Faccount.pem", false)]
    [InlineData("abcdefghijklmnopqrstuv/w", false)]
    public void Only_token_shaped_strings_are_looked_up(string token, bool expected) =>
        Assert.Equal(expected, ChallengeResponder.IsToken(token));

    private static DefaultConnectionContext Connection(ClientHello hello)
    {
        var connection = new DefaultConnectionContext();
        connection.Features.Set(hello);
        return connection;
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);
}
