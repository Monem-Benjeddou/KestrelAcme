using Microsoft.Extensions.Logging;

namespace KestrelAcme;

internal static partial class Log
{
    [LoggerMessage(1, LogLevel.Information, "Loaded the stored certificate for {Domains}, valid until {NotAfter:u}.")]
    public static partial void LoadedCertificate(ILogger logger, string domains, DateTimeOffset notAfter);

    [LoggerMessage(2, LogLevel.Information, "No stored certificate; one will be requested once the server has started.")]
    public static partial void NoStoredCertificate(ILogger logger);

    [LoggerMessage(3, LogLevel.Information, "Ignoring the stored certificate because {Reason}.")]
    public static partial void StoredCertificateIgnored(ILogger logger, string reason);

    [LoggerMessage(4, LogLevel.Warning, "The stored certificate could not be read; a new one will be requested.")]
    public static partial void StoredCertificateUnreadable(ILogger logger, Exception exception);

    [LoggerMessage(5, LogLevel.Information, "ACME account ready: {AccountUrl}.")]
    public static partial void AccountReady(ILogger logger, string accountUrl);

    [LoggerMessage(6, LogLevel.Information, "Ordering a certificate for {Domains} using {ChallengeType}.")]
    public static partial void Ordering(ILogger logger, string domains, string challengeType);

    [LoggerMessage(7, LogLevel.Information, "{Domain} validated with {ChallengeType}.")]
    public static partial void AuthorizationValid(ILogger logger, string domain, string challengeType);

    [LoggerMessage(8, LogLevel.Warning, "Order with {ChallengeType} failed: {Reason}")]
    public static partial void OrderFailed(ILogger logger, string challengeType, string reason);

    [LoggerMessage(9, LogLevel.Information, "Certificate issued for {Domains}, valid until {NotAfter:u} (took {Duration}).")]
    public static partial void Issued(ILogger logger, string domains, DateTimeOffset notAfter, TimeSpan duration);

    [LoggerMessage(10, LogLevel.Information, "Certificate renewal due at {RenewAt:u}; next check in {Wait}.")]
    public static partial void RenewalScheduled(ILogger logger, DateTimeOffset renewAt, TimeSpan wait);

    [LoggerMessage(11, LogLevel.Error, "Certificate issuance failed ({Failures} in a row); retrying in {RetryIn}.")]
    public static partial void RenewalFailed(ILogger logger, Exception exception, int failures, TimeSpan retryIn);

    [LoggerMessage(12, LogLevel.Debug, "Renewal information unavailable, using the default schedule: {Reason}")]
    public static partial void RenewalInfoUnavailable(ILogger logger, string reason);

    [LoggerMessage(13, LogLevel.Debug, "Nonce rejected by {Url} (attempt {Attempt}); retrying with a fresh one.")]
    public static partial void BadNonce(ILogger logger, Uri url, int attempt);

    [LoggerMessage(14, LogLevel.Debug, "Serving the TLS-ALPN-01 challenge certificate for {Domain}.")]
    public static partial void TlsAlpnChallengeServed(ILogger logger, string domain);

    [LoggerMessage(15, LogLevel.Debug, "Could not read the ClientHello on connection {ConnectionId}.")]
    public static partial void ClientHelloPeekFailed(ILogger logger, string connectionId, Exception exception);

    [LoggerMessage(16, LogLevel.Error, "The issued certificate could not be saved; it is served anyway and saving is retried at the next check.")]
    public static partial void StoreWriteFailed(ILogger logger, Exception exception);

    [LoggerMessage(17, LogLevel.Information, "Created DNS TXT record {Name}.")]
    public static partial void DnsRecordAdded(ILogger logger, string name);

    [LoggerMessage(18, LogLevel.Information, "Waiting {Delay} for the DNS records to propagate.")]
    public static partial void WaitingForDns(ILogger logger, TimeSpan delay);

    [LoggerMessage(19, LogLevel.Warning, "Could not remove a challenge response after the order.")]
    public static partial void CleanupFailed(ILogger logger, Exception exception);
}
