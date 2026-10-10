using KestrelAcme.Protocol;

namespace KestrelAcme.Hosting;

/// <summary>When to renew, when to check again and how long to back off. No I/O, so it is unit-tested directly.</summary>
internal static class RenewalPlanner
{
    public static readonly TimeSpan DefaultCheckInterval = TimeSpan.FromHours(12);
    public static readonly TimeSpan MinCheckInterval = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan MaxCheckInterval = TimeSpan.FromHours(24);
    public static readonly TimeSpan FirstRetry = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan MaxRetry = TimeSpan.FromHours(6);

    /// <summary>The longest server-requested wait honoured. Rate-limit Retry-After values can be days.</summary>
    public static readonly TimeSpan MaxServerRetryAfter = TimeSpan.FromDays(7);

    /// <summary>
    /// The moment to renew. In order of precedence: <paramref name="renewBefore"/> from the options; a uniformly
    /// random moment in the CA's suggested window (RFC 9773 §4.2, spreads load); one third of the lifetime before expiry.
    /// </summary>
    public static DateTimeOffset GetRenewalTime(
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        RenewalWindow? window,
        TimeSpan? renewBefore,
        double random)
    {
        if (renewBefore is { } before)
            return notAfter - before;

        if (window is { } w && w.End > w.Start)
            return w.Start + (w.End - w.Start) * random;

        return notAfter - (notAfter - notBefore) / 3;
    }

    /// <summary>How long to sleep before looking again: until the renewal moment, but no longer than the check interval.</summary>
    public static TimeSpan GetWaitTime(DateTimeOffset now, DateTimeOffset renewAt, TimeSpan? serverRetryAfter)
    {
        var check = Clamp(serverRetryAfter ?? DefaultCheckInterval, MinCheckInterval, MaxCheckInterval);
        var untilRenewal = renewAt - now;
        return untilRenewal < check ? Max(untilRenewal, TimeSpan.Zero) : check;
    }

    /// <summary>
    /// Exponential backoff after consecutive failures (5 min, 10, 20 … 6 h), never shorter than the server asked:
    /// retrying a rate-limited order early just gets rate-limited again.
    /// </summary>
    public static TimeSpan GetRetryDelay(int consecutiveFailures, TimeSpan? serverRetryAfter)
    {
        var exponent = Math.Clamp(consecutiveFailures - 1, 0, 20);
        var backoff = TimeSpan.FromTicks(Math.Min(FirstRetry.Ticks << exponent, MaxRetry.Ticks));
        return serverRetryAfter is { } retryAfter && retryAfter > backoff ? Min(retryAfter, MaxServerRetryAfter) : backoff;
    }

    private static TimeSpan Clamp(TimeSpan value, TimeSpan min, TimeSpan max) => value < min ? min : value > max ? max : value;

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;

    private static TimeSpan Min(TimeSpan a, TimeSpan b) => a < b ? a : b;
}
