using System.Diagnostics;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace KestrelAcme.IntegrationTests;

/// <summary>
/// Runs Pebble (Let's Encrypt's test CA) and pebble-challtestsrv (a DNS server resolving every name to 127.0.0.1),
/// built by <c>eng/pebble.sh</c>. Pebble validates HTTP-01 on port 5002 and TLS-ALPN-01 on port 5001.
/// </summary>
public sealed class PebbleFixture : IAsyncLifetime
{
    public const int HttpPort = 5002;
    public const int TlsPort = 5001;

    public static readonly Uri Directory = new("https://localhost:14000/dir");
    public static readonly Uri Management = new("https://localhost:15000/");

    private readonly List<Process> _processes = [];
    private readonly StringBuilder _output = new();

    /// <summary>The folder holding <c>bin/</c> and <c>src/</c>, or null when Pebble hasn't been built.</summary>
    public static string? PebbleRoot { get; } = FindPebble();

    /// <summary>The root that signs Pebble's own HTTPS endpoints (not the certificates it issues).</summary>
    public X509Certificate2 ApiRoot { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        if (PebbleRoot is null)
            return;

        var source = Path.Combine(PebbleRoot, "src");
#if NET9_0_OR_GREATER
        ApiRoot = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(source, "test/certs/pebble.minica.pem"));
#else
        ApiRoot = new X509Certificate2(Path.Combine(source, "test/certs/pebble.minica.pem"));
#endif

        Start("pebble-challtestsrv", source,
            "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "",
            "-dnsserver", "127.0.0.1:8053", "-management", "127.0.0.1:8055",
            "-defaultIPv4", "127.0.0.1", "-defaultIPv6", "");

        Start("pebble", source, "-config", "test/config/pebble-config.json", "-dnsserver", "127.0.0.1:8053");

        using var http = CreateHttpClient();
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            try
            {
                (await http.GetAsync(Directory)).EnsureSuccessStatusCode();
                return;
            }
            catch (HttpRequestException) when (DateTime.UtcNow < deadline)
            {
                await Task.Delay(200);
            }
            catch (HttpRequestException e)
            {
                throw new InvalidOperationException($"Pebble did not start:\n{_output}", e);
            }
        }
    }

    /// <summary>An HTTP client that trusts Pebble's API certificate.</summary>
    public HttpClient CreateHttpClient()
    {
        // Pebble rejects requests without a User-Agent, as RFC 8555 §6.1 requires.
        var client = new HttpClient(CreateHandler());
        client.DefaultRequestHeaders.UserAgent.ParseAdd("KestrelAcme.IntegrationTests");
        return client;
    }

    public HttpMessageHandler CreateHandler() => new SocketsHttpHandler
    {
        SslOptions = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = (_, certificate, _, _) =>
            {
                if (certificate is null)
                    return false;
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(ApiRoot);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(certificate as X509Certificate2 ?? new X509Certificate2(certificate));
            },
        },
    };

    /// <summary>The root that signs issued certificates. Pebble makes a new one on every start.</summary>
    public async Task<X509Certificate2> GetIssuingRootAsync()
    {
        using var http = CreateHttpClient();
        var pem = await http.GetStringAsync(new Uri(Management, "roots/0"));
        return X509Certificate2.CreateFromPem(pem);
    }

    /// <summary>Overrides Pebble's ARI answer for a certificate (management API).</summary>
    public async Task SetRenewalInfoAsync(X509Certificate2 certificate, DateTimeOffset start, DateTimeOffset end)
    {
        using var http = CreateHttpClient();
        var ari = $$$"""{"suggestedWindow":{"start":"{{{start:O}}}","end":"{{{end:O}}}"}}""";
        var body = System.Text.Json.JsonSerializer.Serialize(new { Certificate = certificate.ExportCertificatePem(), ARIResponse = ari });
        (await http.PostAsync(new Uri(Management, "set-renewal-info/"), new StringContent(body))).EnsureSuccessStatusCode();
    }

    private void Start(string name, string workingDirectory, params string[] arguments)
    {
        var start = new ProcessStartInfo(Path.Combine(PebbleRoot!, "bin", OperatingSystem.IsWindows() ? name + ".exe" : name))
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        start.Environment["PEBBLE_VA_NOSLEEP"] = "1";

        var process = Process.Start(start)!;
        process.OutputDataReceived += (_, e) => { lock (_output) _output.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { lock (_output) _output.AppendLine(e.Data); };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        _processes.Add(process);
    }

    public string Output
    {
        get { lock (_output) return _output.ToString(); }
    }

    public Task DisposeAsync()
    {
        foreach (var process in _processes)
        {
            try
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5000);
            }
            catch (InvalidOperationException)
            {
            }
            process.Dispose();
        }
        return Task.CompletedTask;
    }

    private static string? FindPebble()
    {
        if (Environment.GetEnvironmentVariable("PEBBLE_ROOT") is { Length: > 0 } configured)
            return configured;

        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, ".pebble");
            if (File.Exists(Path.Combine(candidate, "bin", OperatingSystem.IsWindows() ? "pebble.exe" : "pebble")))
                return candidate;
        }
        return null;
    }
}

[CollectionDefinition(Name)]
public sealed class PebbleCollection : ICollectionFixture<PebbleFixture>
{
    public const string Name = "Pebble";
}

/// <summary>A test that needs Pebble; skipped with a hint when it hasn't been built.</summary>
public sealed class PebbleFactAttribute : FactAttribute
{
    public PebbleFactAttribute()
    {
        if (PebbleFixture.PebbleRoot is null)
            Skip = "Pebble is not built. Run eng/pebble.sh (needs Go) or set PEBBLE_ROOT.";
    }
}
