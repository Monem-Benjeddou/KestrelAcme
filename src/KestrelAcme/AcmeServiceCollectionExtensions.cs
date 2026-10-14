using KestrelAcme.Diagnostics;
using KestrelAcme.Hosting;
using KestrelAcme.Storage;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace KestrelAcme;

/// <summary>Registers automatic HTTPS certificates for Kestrel.</summary>
public static class AcmeServiceCollectionExtensions
{
    /// <summary>
    /// The name of the <see cref="HttpClient"/> used to talk to the certificate authority. Configure it with
    /// <c>services.AddHttpClient(AcmeServiceCollectionExtensions.HttpClientName)</c>, to set a proxy for instance.
    /// </summary>
    public const string HttpClientName = "KestrelAcme";

    /// <summary>
    /// Obtains a certificate for the configured domains from an ACME certificate authority (Let's Encrypt by
    /// default), serves it on every Kestrel HTTPS endpoint that has no certificate of its own, and renews it.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddKestrelAcme(o =>
    /// {
    ///     o.Domains.Add("example.com");
    ///     o.Email = "ops@example.com";
    ///     o.AcceptTermsOfService = true;
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddKestrelAcme(this IServiceCollection services, Action<AcmeOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        services.AddCore().Configure(configure);
        return services;
    }

    /// <summary>Same as <see cref="AddKestrelAcme(IServiceCollection, Action{AcmeOptions})"/>, bound to a configuration section.</summary>
    /// <example><c>builder.Services.AddKestrelAcme(builder.Configuration.GetSection("Acme"));</c></example>
    public static IServiceCollection AddKestrelAcme(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        services.AddCore().Bind(configuration);
        return services;
    }

    /// <summary>Adds a health check that reports the state of the served certificate.</summary>
    public static IHealthChecksBuilder AddKestrelAcme(
        this IHealthChecksBuilder builder, string name = "kestrel-acme", HealthStatus? failureStatus = null, IEnumerable<string>? tags = null)
    {
        builder.Services.TryAddSingleton<AcmeHealthCheck>();
        return builder.Add(new HealthCheckRegistration(
            name, sp => sp.GetRequiredService<AcmeHealthCheck>(), failureStatus, tags));
    }

    private static OptionsBuilder<AcmeOptions> AddCore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        var options = services.AddOptions<AcmeOptions>();

        // Calling AddKestrelAcme twice only adds configuration.
        if (services.Any(d => d.ServiceType == typeof(AcmeRenewalService)))
            return options;

        options.ValidateOnStart();
        services.AddSingleton<IPostConfigureOptions<AcmeOptions>, AcmeOptionsNormalizer>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<AcmeOptions>, AcmeOptionsValidator>());

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IAcmeStore, FileSystemAcmeStore>();
        // The file lock only coordinates instances that share the file store; a custom store needs its own lock.
        services.TryAddSingleton<IAcmeLock>(sp => sp.GetRequiredService<IAcmeStore>() is FileSystemAcmeStore files
            ? new FileSystemAcmeLock(files)
            : new UncoordinatedAcmeLock());
        services.AddSingleton<CertificateSelector>();
        services.AddSingleton<ChallengeResponder>();
        services.AddSingleton<AcmeCertificateIssuer>();
        services.AddSingleton<AcmeMetrics>();
        services.AddMetrics();

        services.AddHttpClient(HttpClientName, client =>
        {
            client.DefaultRequestHeaders.UserAgent.ParseAdd($"KestrelAcme/{typeof(AcmeOptions).Assembly.GetName().Version?.ToString(3)}");
            client.Timeout = TimeSpan.FromSeconds(30);
        });

        services.AddSingleton<AcmeRenewalService>();
        services.AddHostedService(sp => sp.GetRequiredService<AcmeRenewalService>());
        services.AddTransient<IStartupFilter, Http01ChallengeStartupFilter>();
        // First in line: endpoint and HTTPS defaults only apply to endpoints created after they are set, so this
        // must run before any ConfigureKestrel(o => o.Listen(...)) the app registered before calling us.
        services.Insert(0, ServiceDescriptor.Transient<IConfigureOptions<KestrelServerOptions>, KestrelOptionsSetup>());

        return options;
    }
}
