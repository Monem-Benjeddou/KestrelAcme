using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using KestrelAcme.Certificates;
using KestrelAcme.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit.Abstractions;

namespace KestrelAcme.IntegrationTests;

/// <summary>A real Kestrel app using KestrelAcme against Pebble, listening where Pebble validates challenges.</summary>
internal sealed class TestApp : IAsyncDisposable
{
    private readonly WebApplication _app;

    private TestApp(WebApplication app) => _app = app;

    public CertificateSelector Selector => _app.Services.GetRequiredService<CertificateSelector>();
    public AcmeRenewalService Renewal => _app.Services.GetRequiredService<AcmeRenewalService>();

    public static async Task<TestApp> StartAsync(
        PebbleFixture pebble, ITestOutputHelper output, string domain, string storagePath, Action<AcmeOptions>? configure = null,
        Action<IServiceCollection>? services = null, int httpPort = PebbleFixture.HttpPort, int tlsPort = PebbleFixture.TlsPort)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = AppContext.BaseDirectory });
        builder.Logging.ClearProviders().AddProvider(new TestOutputLoggerProvider(output)).SetMinimumLevel(LogLevel.Debug);
        builder.WebHost.UseUrls($"http://127.0.0.1:{httpPort}", $"https://127.0.0.1:{tlsPort}");

        builder.Services.AddKestrelAcme(o =>
        {
            o.Domains.Add(domain);
            o.Email = "ops@example.org";
            o.AcceptTermsOfService = true;
            o.DirectoryUri = PebbleFixture.Directory;
            o.StoragePath = storagePath;
            o.IssuanceTimeout = TimeSpan.FromSeconds(60);
            configure?.Invoke(o);
        });
        services?.Invoke(builder.Services);
        builder.Services.AddHttpClient(AcmeServiceCollectionExtensions.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(pebble.CreateHandler);

        var app = builder.Build();
        app.MapGet("/", () => "hello over https");
        await app.StartAsync();
        return new TestApp(app);
    }

    /// <summary>Waits until a CA-issued certificate is being served (other than <paramref name="previous"/>).</summary>
    public async Task<CertificateBundle> WaitForCertificateAsync(string? previousThumbprint = null)
    {
        var deadline = DateTime.UtcNow.AddSeconds(60);
        while (DateTime.UtcNow < deadline)
        {
            var current = Selector.Current;
            if (!current.IsFallback && current.Leaf.Thumbprint != previousThumbprint)
                return current;
            await Task.Delay(100);
        }
        throw new TimeoutException("No certificate was issued within 60 seconds.");
    }

    /// <summary>Connects like a browser would and returns what the server presented.</summary>
    public static async Task<(X509Certificate2 Leaf, List<X509Certificate2> Chain, string Protocol)> HandshakeAsync(string serverName)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", PebbleFixture.TlsPort);

        X509Certificate2? leaf = null;
        var chain = new List<X509Certificate2>();
        await using var ssl = new SslStream(tcp.GetStream());
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = serverName,
            ApplicationProtocols = [SslApplicationProtocol.Http11],
            RemoteCertificateValidationCallback = (_, certificate, x509Chain, _) =>
            {
                leaf = new X509Certificate2(certificate!);
                foreach (var element in x509Chain!.ChainElements)
                    chain.Add(new X509Certificate2(element.Certificate));
                return true;
            },
        });
        return (leaf!, chain, ssl.NegotiatedApplicationProtocol.ToString());
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}

internal sealed class TestOutputLoggerProvider(ITestOutputHelper output) : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new TestOutputLogger(output, categoryName);

    public void Dispose()
    {
    }

    private sealed class TestOutputLogger(ITestOutputHelper output, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) =>
            category.StartsWith("KestrelAcme", StringComparison.Ordinal) || logLevel >= LogLevel.Warning;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
                return;
            try
            {
                output.WriteLine($"{logLevel,-11} {category[(category.LastIndexOf('.') + 1)..]}: {formatter(state, exception)}{(exception is null ? "" : "\n" + exception)}");
            }
            catch (InvalidOperationException)
            {
                // The test has finished; xunit no longer accepts output.
            }
        }
    }
}
