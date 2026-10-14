using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;

namespace KestrelAcme.Kubernetes;

/// <summary>The few Kubernetes API calls KestrelAcme needs, as plain HTTP with the pod's service account.</summary>
internal sealed class KubernetesApi(IHttpClientFactory httpClientFactory, IOptions<KubernetesAcmeOptions> options)
{
    private readonly Lazy<(Uri Server, string Namespace)> _target = new(() => Resolve(options.Value));

    private KubernetesAcmeOptions Options => options.Value;

    public string SecretsPath => $"api/v1/namespaces/{_target.Value.Namespace}/secrets";

    public string LeasesPath => $"apis/coordination.k8s.io/v1/namespaces/{_target.Value.Namespace}/leases";

    /// <summary>
    /// A valid object name for a store key or lock name: the prefix and a hash, since keys contain slashes and can be
    /// longer than names may be.
    /// </summary>
    public string ObjectName(string kind, string key)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..20].ToLowerInvariant();
        return $"{Options.Name}-{kind}-{hash}";
    }

    /// <summary>Sends a request. Returns the status and the parsed body, or throws for statuses other than 2xx, 404 and 409.</summary>
    public async Task<(HttpStatusCode Status, JsonNode? Body)> SendAsync(
        HttpMethod method, string path, JsonNode? body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, new Uri(_target.Value.Server, path));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", (await File.ReadAllTextAsync(Options.TokenPath, cancellationToken).ConfigureAwait(false)).Trim());
        if (body is not null)
            request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");

        using var client = httpClientFactory.CreateClient(KubernetesAcmeServiceCollectionExtensions.HttpClientName);
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode && response.StatusCode is not (HttpStatusCode.NotFound or HttpStatusCode.Conflict))
        {
            // The API server explains in a Status object, e.g. which RBAC permission is missing.
            var reason = TryParse(text)?["message"]?.GetValue<string>() ?? text;
            throw new HttpRequestException($"Kubernetes API {method} {path} failed with {(int)response.StatusCode}: {reason}", null, response.StatusCode);
        }
        return (response.StatusCode, TryParse(text));
    }

    /// <summary>Trusts the cluster's certificate authority for the API server.</summary>
    internal static HttpMessageHandler CreateHandler(KubernetesAcmeOptions options)
    {
        var handler = new SocketsHttpHandler();
        if (!File.Exists(options.CertificateAuthorityPath))
            return handler;

        var roots = new X509Certificate2Collection();
        roots.ImportFromPemFile(options.CertificateAuthorityPath);
        handler.SslOptions = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
            {
                if (certificate is null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
                    return false;
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.AddRange(roots);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(certificate as X509Certificate2 ?? new X509Certificate2(certificate));
            },
        };
        return handler;
    }

    private static (Uri, string) Resolve(KubernetesAcmeOptions options)
    {
        var server = options.ApiServer;
        if (server is null)
        {
            var host = Environment.GetEnvironmentVariable("KUBERNETES_SERVICE_HOST");
            var port = Environment.GetEnvironmentVariable("KUBERNETES_SERVICE_PORT");
            if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(port))
                throw new InvalidOperationException(
                    "Not running in a Kubernetes pod (KUBERNETES_SERVICE_HOST is not set). Set KubernetesAcmeOptions.ApiServer.");
            server = new UriBuilder(Uri.UriSchemeHttps, host, int.Parse(port, System.Globalization.CultureInfo.InvariantCulture)).Uri;
        }

        var ns = options.Namespace;
        if (string.IsNullOrEmpty(ns))
        {
            var file = Path.Combine(Path.GetDirectoryName(options.TokenPath)!, "namespace");
            ns = File.Exists(file) ? File.ReadAllText(file).Trim() : throw new InvalidOperationException(
                $"The pod's namespace is unknown ({file} doesn't exist). Set KubernetesAcmeOptions.Namespace.");
        }

        return (server.AbsolutePath.EndsWith('/') ? server : new Uri(server + "/"), ns);
    }

    private static JsonNode? TryParse(string text)
    {
        try
        {
            return text.Length == 0 ? null : JsonNode.Parse(text);
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
    }
}
