using KestrelAcme.Hosting;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace KestrelAcme.Diagnostics;

/// <summary>
/// Healthy while a CA-issued certificate has more than <see cref="ExpiryWarning"/> left; degraded while the
/// placeholder is served or expiry is close; unhealthy once it has expired.
/// </summary>
internal sealed class AcmeHealthCheck(CertificateSelector selector, TimeProvider time) : IHealthCheck
{
    public static readonly TimeSpan ExpiryWarning = TimeSpan.FromDays(7);

    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var certificate = selector.Current;
        if (certificate.IsFallback)
            return Task.FromResult(HealthCheckResult.Degraded("No certificate has been issued yet; serving a self-signed placeholder."));

        var left = certificate.NotAfter - time.GetUtcNow();
        var data = new Dictionary<string, object>
        {
            ["domains"] = string.Join(", ", certificate.DnsNames),
            ["notAfter"] = certificate.NotAfter,
        };

        var result = left <= TimeSpan.Zero
            ? new HealthCheckResult(context.Registration.FailureStatus, "The certificate has expired.", data: data)
            : left < ExpiryWarning
                ? HealthCheckResult.Degraded($"The certificate expires in {left.TotalHours:F0} hours.", data: data)
                : HealthCheckResult.Healthy($"The certificate is valid until {certificate.NotAfter:u}.", data);

        return Task.FromResult(result);
    }
}
