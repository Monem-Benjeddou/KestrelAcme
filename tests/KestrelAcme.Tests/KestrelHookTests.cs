using System.Net.Security;
using KestrelAcme.Certificates;
using KestrelAcme.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace KestrelAcme.Tests;

public class KestrelHookTests
{
    private readonly CertificateSelector _selector;
    private readonly ChallengeResponder _challenges = new();
    private readonly KestrelOptionsSetup _setup;

    public KestrelHookTests()
    {
        var options = new AcmeOptions();
        options.Domains.Add("example.com");
        _selector = new CertificateSelector(Options.Create(options), TimeProvider.System);
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
    public async Task Http01_answers_known_tokens_and_passes_everything_else_on(string method, string path, int status, string body)
    {
        _challenges.AddHttp01("tok", "tok.thumb");
        var app = new ApplicationBuilder(new ServiceCollection().BuildServiceProvider());
        new Http01ChallengeStartupFilter(_challenges).Configure(a => a.Run(c =>
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

    private static DefaultConnectionContext Connection(ClientHello hello)
    {
        var connection = new DefaultConnectionContext();
        connection.Features.Set(hello);
        return connection;
    }
}
