using KestrelAcme.Kubernetes;
using KestrelAcme.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace KestrelAcme.Kubernetes
{
    /// <summary>Where and how KestrelAcme keeps its state in Kubernetes.</summary>
    public sealed class KubernetesAcmeOptions
    {
        /// <summary>
        /// Prefix of the Secret and Lease names: up to 40 lowercase letters, digits and dashes. Apps in one namespace
        /// that should not share an ACME account or certificates need different names.
        /// </summary>
        public string Name { get; set; } = "kestrelacme";

        /// <summary>The namespace of the Secrets and Leases. Defaults to the pod's own.</summary>
        public string? Namespace { get; set; }

        /// <summary>The API server. Defaults to the in-cluster address (<c>KUBERNETES_SERVICE_HOST</c> and <c>_PORT</c>).</summary>
        public Uri? ApiServer { get; set; }

        /// <summary>The service account token, read again for every request since Kubernetes rotates it.</summary>
        public string TokenPath { get; set; } = "/var/run/secrets/kubernetes.io/serviceaccount/token";

        /// <summary>The certificate authority that signs the API server's certificate.</summary>
        public string CertificateAuthorityPath { get; set; } = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
    }
}

namespace KestrelAcme
{
    /// <summary>Registers Kubernetes as KestrelAcme's shared state.</summary>
    public static class KubernetesAcmeServiceCollectionExtensions
    {
        /// <summary>The name of the <see cref="HttpClient"/> used to call the Kubernetes API.</summary>
        public const string HttpClientName = "KestrelAcme.Kubernetes";

        /// <summary>
        /// Keeps the account key, certificates and challenge answers in Kubernetes Secrets, and lets one replica at a
        /// time order the certificate through a Lease. Replicas of a Deployment then share one certificate, without
        /// a shared volume. Talks to the API server directly: no client library needed. The service account needs
        /// get, create, update and delete on <c>secrets</c>, and get, create and update on <c>leases</c>.
        /// </summary>
        public static IServiceCollection AddKestrelAcmeKubernetes(this IServiceCollection services, Action<KubernetesAcmeOptions>? configure = null)
        {
            ArgumentNullException.ThrowIfNull(services);
            var options = services.AddOptions<KubernetesAcmeOptions>();
            if (configure is not null)
                options.Configure(configure);
            options.Validate(o => IsValidName(o.Name),
                    "KubernetesAcmeOptions.Name must be 1 to 40 lowercase letters, digits or dashes, starting and ending with a letter or digit.")
                .ValidateOnStart();

            services.TryAddSingleton(TimeProvider.System);
            services.AddSingleton<KubernetesApi>();
            services.AddSingleton<IAcmeStore, KubernetesSecretStore>();
            services.AddSingleton<IAcmeLock, KubernetesLeaseLock>();
            services.AddHttpClient(HttpClientName)
                .ConfigurePrimaryHttpMessageHandler(sp => KubernetesApi.CreateHandler(sp.GetRequiredService<IOptions<KubernetesAcmeOptions>>().Value));
            return services;
        }

        /// <summary>Usable as the start of a Kubernetes object name (RFC 1123), leaving room for the rest.</summary>
        internal static bool IsValidName(string? name) =>
            name is { Length: > 0 and <= 40 } && char.IsAsciiLetterOrDigit(name[0]) && char.IsAsciiLetterOrDigit(name[^1])
            && name.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-');
    }
}
