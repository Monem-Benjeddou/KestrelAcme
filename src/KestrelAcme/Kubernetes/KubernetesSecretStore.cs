using System.Net;
using System.Text.Json.Nodes;
using KestrelAcme.Storage;

namespace KestrelAcme.Kubernetes;

/// <summary>
/// Keeps each value in a Secret of its own, so that writes are plain replacements: no read-modify-write race between
/// replicas saving a certificate and sharing challenge answers at the same time.
/// </summary>
internal sealed class KubernetesSecretStore(KubernetesApi api) : IAcmeStore
{
    public async Task<byte[]?> ReadAsync(string key, CancellationToken cancellationToken)
    {
        var (status, secret) = await api.SendAsync(HttpMethod.Get, $"{api.SecretsPath}/{api.ObjectName("store", key)}", null, cancellationToken)
            .ConfigureAwait(false);
        return status == HttpStatusCode.NotFound || secret?["data"]?["value"]?.GetValue<string>() is not { } value
            ? null
            : Convert.FromBase64String(value);
    }

    public async Task WriteAsync(string key, byte[] value, CancellationToken cancellationToken)
    {
        var name = api.ObjectName("store", key);
        var secret = new JsonObject
        {
            ["apiVersion"] = "v1",
            ["kind"] = "Secret",
            ["metadata"] = new JsonObject
            {
                ["name"] = name,
                ["labels"] = new JsonObject { ["app.kubernetes.io/managed-by"] = "kestrelacme" },
                ["annotations"] = new JsonObject { ["kestrelacme/key"] = key },
            },
            ["type"] = "Opaque",
            ["data"] = new JsonObject { ["value"] = Convert.ToBase64String(value) },
        };

        // Replace; create if missing; replace after all if another replica created it in between.
        var (status, _) = await api.SendAsync(HttpMethod.Put, $"{api.SecretsPath}/{name}", secret, cancellationToken).ConfigureAwait(false);
        if (status == HttpStatusCode.NotFound)
            (status, _) = await api.SendAsync(HttpMethod.Post, api.SecretsPath, secret, cancellationToken).ConfigureAwait(false);
        if (status == HttpStatusCode.Conflict)
            (status, _) = await api.SendAsync(HttpMethod.Put, $"{api.SecretsPath}/{name}", secret, cancellationToken).ConfigureAwait(false);
        if (status is HttpStatusCode.NotFound or HttpStatusCode.Conflict)
            throw new HttpRequestException($"Could not write Secret {name}: {(int)status}.", null, status);
    }

    public Task DeleteAsync(string key, CancellationToken cancellationToken) =>
        api.SendAsync(HttpMethod.Delete, $"{api.SecretsPath}/{api.ObjectName("store", key)}", null, cancellationToken); // 404 is fine
}
