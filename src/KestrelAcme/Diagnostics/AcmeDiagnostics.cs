using System.Diagnostics;
using System.Diagnostics.Metrics;
using KestrelAcme.Hosting;

namespace KestrelAcme.Diagnostics;

/// <summary>Names to subscribe to with OpenTelemetry: <c>AddSource("KestrelAcme")</c> and <c>AddMeter("KestrelAcme")</c>.</summary>
public static class AcmeDiagnostics
{
    /// <summary>The name of the <see cref="ActivitySource"/> and the <see cref="Meter"/>.</summary>
    public const string Name = "KestrelAcme";

    internal static readonly ActivitySource ActivitySource = new(Name, typeof(AcmeDiagnostics).Assembly.GetName().Version?.ToString());

    internal static Activity? StartActivity(string operation, Uri url)
    {
        var activity = ActivitySource.StartActivity($"acme {operation}", ActivityKind.Client);
        activity?.SetTag("url.full", url.AbsoluteUri);
        return activity;
    }
}

internal sealed class AcmeMetrics
{
    private readonly Counter<long> _issuances;
    private readonly Histogram<double> _issuanceDuration;

    public AcmeMetrics(IMeterFactory meterFactory, CertificateSelector selector, TimeProvider time)
    {
        var meter = meterFactory.Create(AcmeDiagnostics.Name);

        _issuances = meter.CreateCounter<long>(
            "kestrelacme.issuances",
            unit: "{certificate}",
            description: "Certificate orders, by result.");

        _issuanceDuration = meter.CreateHistogram<double>(
            "kestrelacme.issuance.duration",
            unit: "s",
            description: "Time from new order to downloaded certificate.");

        meter.CreateObservableGauge(
            "kestrelacme.certificate.time_to_expiry",
            () => selector.Current is { IsFallback: false } current
                ? [new Measurement<double>((current.NotAfter - time.GetUtcNow()).TotalSeconds)]
                : Array.Empty<Measurement<double>>(),
            unit: "s",
            description: "Time left before the served certificate expires.");
    }

    public void RecordIssuance(bool success, TimeSpan duration)
    {
        var result = new KeyValuePair<string, object?>("result", success ? "success" : "failure");
        _issuances.Add(1, result);
        _issuanceDuration.Record(duration.TotalSeconds, result);
    }
}
