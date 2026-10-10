using System.Text;
using KestrelAcme.Certificates;
using KestrelAcme.Protocol;
using KestrelAcme.Storage;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace KestrelAcme.Hosting;

/// <summary>Runs ACME orders: account setup, challenges, finalization and download (RFC 8555 §7.4).</summary>
internal sealed class AcmeCertificateIssuer(
    IHttpClientFactory httpClientFactory,
    IAcmeStore store,
    ChallengeResponder challenges,
    IServer server,
    IEnumerable<IDnsChallengeProvider> dnsProviders,
    IOptions<AcmeOptions> options,
    TimeProvider time,
    ILogger<AcmeCertificateIssuer> logger)
{
    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan MaxPollInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan CleanupTimeout = TimeSpan.FromSeconds(30);

    // The last registered provider wins, as usual for DI.
    private readonly IDnsChallengeProvider? _dns = dnsProviders.LastOrDefault();

    private readonly SemaphoreSlim _clientLock = new(1, 1);
    private AcmeClient? _client;

    // The challenge type that last worked, tried first next time; the one that last failed, tried last.
    // Failed validations count against the CA's rate limits (5 per hostname per hour at Let's Encrypt).
    private string? _lastSucceeded;
    private string? _lastFailed;

    private AcmeOptions Options => options.Value;

    /// <summary>
    /// The store key of the certificate. It includes the CA directory, so switching from staging to production
    /// doesn't keep serving the staging certificate.
    /// </summary>
    public string CertificateKey => $"certificates/{StoreName(Options.DirectoryUri)}/{FileName(Options.Domains[0])}.pfx";

    /// <summary>A domain as a file name: <c>*</c> isn't allowed in Windows file names.</summary>
    internal static string FileName(string domain) =>
        domain.StartsWith("*.", StringComparison.Ordinal) ? "_wildcard." + domain[2..] : domain;

    private string AccountKeyKey => $"accounts/{StoreName(Options.DirectoryUri)}/account.pem";

    /// <summary>
    /// A file-name-safe name for a CA directory: host, port when not 443, then path, e.g.
    /// <c>acme-v02.api.letsencrypt.org_directory</c>. Two directories on one host get different names.
    /// </summary>
    internal static string StoreName(Uri directory)
    {
        var raw = directory.IsDefaultPort ? directory.Host + directory.AbsolutePath : $"{directory.Host}_{directory.Port}{directory.AbsolutePath}";
        var name = new System.Text.StringBuilder(raw.Length);
        foreach (var c in raw.TrimEnd('/').ToLowerInvariant())
            name.Append(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' ? c : '_');
        return name.ToString();
    }

    /// <summary>The ACME client with a ready account, created on first use.</summary>
    public async Task<AcmeClient> GetClientAsync(CancellationToken cancellationToken)
    {
        if (_client is not null)
            return _client;

        await _clientLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_client is not null)
                return _client;

            var key = await LoadOrCreateAccountKeyAsync(cancellationToken).ConfigureAwait(false);
            var client = new AcmeClient(
                () => httpClientFactory.CreateClient(AcmeServiceCollectionExtensions.HttpClientName), Options.DirectoryUri, key, logger);
            await client.CreateAccountAsync(Options.Email, Options.AcceptTermsOfService, Options.ExternalAccountBinding, cancellationToken)
                .ConfigureAwait(false);
            Log.AccountReady(logger, client.AccountUrl!);
            return _client = client;
        }
        finally
        {
            _clientLock.Release();
        }
    }

    /// <summary>Orders a certificate, trying each usable challenge type in turn.</summary>
    /// <param name="replaces">ARI identifier of the certificate being renewed, if any (RFC 9773 §5).</param>
    /// <param name="cancellationToken">Stops the order.</param>
    public async Task<CertificateBundle> IssueAsync(string? replaces, CancellationToken cancellationToken)
    {
        var challengeTypes = GetChallengeTypes();
        if (challengeTypes.Count == 0)
            throw new AcmeException(
                "No enabled challenge type can be answered: HTTP-01 needs an http:// endpoint, TLS-ALPN-01 an https:// "
                + "endpoint and DNS-01 a registered IDnsChallengeProvider.");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Options.IssuanceTimeout);

        try
        {
            var client = await GetClientAsync(timeout.Token).ConfigureAwait(false);
            AcmeException? lastError = null;

            // Attempt i prefers challengeTypes[i]; each authorization uses the first preferred type it offers,
            // so a wildcard name can use DNS-01 while the plain name in the same order uses TLS-ALPN-01.
            for (var i = 0; i < challengeTypes.Count; i++)
            {
                var preference = challengeTypes.Skip(i).Concat(challengeTypes.Take(i)).ToList();
                try
                {
                    var issued = await IssueWithAsync(client, preference, replaces, timeout.Token).ConfigureAwait(false);
                    _lastSucceeded = preference[0];
                    if (_lastFailed == preference[0])
                        _lastFailed = null;
                    return issued;
                }
                catch (AcmeException e) when (e.ProblemType == AcmeProblem.AlreadyReplaced && replaces is not null)
                {
                    // The CA won't accept "replaces" for this certificate (already renewed elsewhere, say).
                    // It's only a hint: retry the same preference without it.
                    Log.OrderFailed(logger, preference[0], e.Message);
                    replaces = null;
                    i--;
                }
                catch (AcmeException e) when (e.ProblemType is not (AcmeProblem.RateLimited or AcmeProblem.Unauthorized or AcmeProblem.AccountDoesNotExist))
                {
                    Log.OrderFailed(logger, preference[0], e.Message);
                    _lastFailed = preference[0];
                    lastError = e;
                }
            }

            throw lastError!;
        }
        catch (AcmeException e) when (e.ProblemType is AcmeProblem.Unauthorized or AcmeProblem.AccountDoesNotExist)
        {
            // The account was deactivated or the CA forgot it: start over with a fresh registration next time.
            _client = null;
            throw;
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new AcmeException($"The certificate was not issued within {Options.IssuanceTimeout}.");
        }
    }

    private async Task<CertificateBundle> IssueWithAsync(
        AcmeClient client, IReadOnlyList<string> preference, string? replaces, CancellationToken cancellationToken)
    {
        Log.Ordering(logger, string.Join(", ", Options.Domains), preference[0]);

        var order = await client.NewOrderAsync(Options.Domains, Options.Profile, replaces, cancellationToken).ConfigureAwait(false);
        var orderUrl = order.Location ?? throw new AcmeException("The certificate authority did not return an order URL.");

        var cleanup = new List<Func<Task>>();
        try
        {
            // 1. Put every challenge response in place.
            var pending = new List<PendingChallenge>();
            foreach (var authorizationUrl in order.Value.Authorizations)
            {
                var authorization = (await client.GetAuthorizationAsync(authorizationUrl, cancellationToken).ConfigureAwait(false)).Value;
                if (authorization.Status == AcmeStatus.Valid)
                    continue; // Validated recently; the CA reuses it.

                var challenge = await PrepareAsync(client, authorization, preference, cleanup, cancellationToken).ConfigureAwait(false);
                pending.Add(new PendingChallenge(authorizationUrl, authorization.Identifier.Value, challenge));
            }

            // 2. Give new DNS records time to reach the authoritative servers.
            if (pending.Any(p => p.Challenge.Type == AcmeChallenge.Dns01) && Options.DnsPropagationDelay > TimeSpan.Zero)
            {
                Log.WaitingForDns(logger, Options.DnsPropagationDelay);
                await Task.Delay(Options.DnsPropagationDelay, time, cancellationToken).ConfigureAwait(false);
            }

            // 3. Ask for validation of all of them, then wait: the CA checks them in parallel.
            foreach (var p in pending)
                await client.AnswerChallengeAsync(p.Challenge.Url, cancellationToken).ConfigureAwait(false);
            foreach (var p in pending)
                await WaitForValidationAsync(client, p, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await CleanUpAsync(cleanup).ConfigureAwait(false);
        }

        var current = await PollOrderAsync(client, orderUrl, AcmeStatus.Ready, cancellationToken).ConfigureAwait(false);

        var (csr, key) = CertificateFactory.CreateSigningRequest(Options.Domains.ToList(), Options.KeyAlgorithm);
        using (key)
        {
            current = (await client.FinalizeAsync(current.Finalize, csr, cancellationToken).ConfigureAwait(false)).Value;
            if (current.Status != AcmeStatus.Valid)
                current = await PollOrderAsync(client, orderUrl, AcmeStatus.Valid, cancellationToken).ConfigureAwait(false);

            var certificateUrl = current.Certificate ?? throw new AcmeException("The order is valid but has no certificate URL.");
            var pem = await client.DownloadCertificateAsync(certificateUrl, cancellationToken).ConfigureAwait(false);
            return CertificateFactory.FromPemChain(pem, key);
        }
    }

    private sealed record PendingChallenge(Uri AuthorizationUrl, string Domain, AcmeChallenge Challenge);

    /// <summary>Picks the challenge for one authorization and serves (or publishes) its response.</summary>
    private async Task<AcmeChallenge> PrepareAsync(
        AcmeClient client, AcmeAuthorization authorization, IReadOnlyList<string> preference, List<Func<Task>> cleanup,
        CancellationToken cancellationToken)
    {
        // For "*.example.com" the identifier is "example.com" with wildcard: true (RFC 8555 §7.1.4).
        var domain = authorization.Identifier.Value;
        var shown = authorization.Wildcard ? "*." + domain : domain;

        var challenge = preference
            .Select(type => authorization.Challenges.FirstOrDefault(c => c.Type == type))
            .FirstOrDefault(c => c is not null)
            ?? throw new AcmeException(
                $"None of the usable challenge types ({string.Join(", ", preference)}) was offered for {shown}. Offered: "
                + string.Join(", ", authorization.Challenges.Select(c => c.Type)) + ".");
        if (challenge.Token is null)
            throw new AcmeException($"The {challenge.Type} challenge for {shown} has no token.");

        var keyAuthorization = client.Key.KeyAuthorization(challenge.Token);
        switch (challenge.Type)
        {
            case AcmeChallenge.Http01:
                challenges.AddHttp01(challenge.Token, keyAuthorization);
                cleanup.Add(() =>
                {
                    challenges.RemoveHttp01(challenge.Token);
                    return Task.CompletedTask;
                });
                break;

            case AcmeChallenge.TlsAlpn01:
                challenges.AddTlsAlpn01(domain, CertificateFactory.CreateTlsAlpnChallenge(domain, keyAuthorization, time.GetUtcNow()));
                cleanup.Add(() =>
                {
                    if (challenges.RemoveTlsAlpn01(domain, out var certificate))
                        certificate.Retire(time);
                    return Task.CompletedTask;
                });
                break;

            case AcmeChallenge.Dns01:
                var name = Dns01RecordName(domain);
                var value = Dns01RecordValue(keyAuthorization);
                await _dns!.AddTxtRecordAsync(name, value, cancellationToken).ConfigureAwait(false);
                Log.DnsRecordAdded(logger, name);
                cleanup.Add(() => _dns.RemoveTxtRecordAsync(name, value, CancellationToken.None));
                break;
        }

        return challenge;
    }

    private async Task WaitForValidationAsync(AcmeClient client, PendingChallenge pending, CancellationToken cancellationToken)
    {
        while (true)
        {
            var response = await client.GetAuthorizationAsync(pending.AuthorizationUrl, cancellationToken).ConfigureAwait(false);
            var authorization = response.Value;

            switch (authorization.Status)
            {
                case AcmeStatus.Valid:
                    Log.AuthorizationValid(logger, pending.Domain, pending.Challenge.Type);
                    return;
                case AcmeStatus.Pending:
                    await DelayAsync(response.RetryAfter, cancellationToken).ConfigureAwait(false);
                    break;
                default:
                    var problem = authorization.Challenges.FirstOrDefault(c => c.Type == pending.Challenge.Type)?.Error;
                    throw new AcmeException(
                        $"Validation of {pending.Domain} with {pending.Challenge.Type} failed: {problem?.ToString() ?? authorization.Status}",
                        problem?.Type);
            }
        }
    }

    /// <summary>Removes challenge responses. Failures are logged, not thrown: the order's outcome matters more.</summary>
    private async Task CleanUpAsync(List<Func<Task>> cleanup)
    {
        foreach (var remove in cleanup)
        {
            try
            {
                await remove().WaitAsync(CleanupTimeout, time).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                Log.CleanupFailed(logger, e);
            }
        }
    }

    /// <summary>The TXT record name for a DNS-01 challenge (RFC 8555 §8.4).</summary>
    internal static string Dns01RecordName(string domain) => "_acme-challenge." + domain;

    /// <summary>The TXT record value: base64url of the SHA-256 of the key authorization (RFC 8555 §8.4).</summary>
    internal static string Dns01RecordValue(string keyAuthorization) =>
        Base64Url.Encode(System.Security.Cryptography.SHA256.HashData(Encoding.ASCII.GetBytes(keyAuthorization)));

    private async Task<AcmeOrder> PollOrderAsync(AcmeClient client, Uri orderUrl, string target, CancellationToken cancellationToken)
    {
        while (true)
        {
            var response = await client.GetOrderAsync(orderUrl, cancellationToken).ConfigureAwait(false);
            var order = response.Value;

            if (order.Status == target)
                return order;
            if (order.Status == AcmeStatus.Invalid)
                throw new AcmeException($"The order became invalid: {order.Error?.ToString() ?? "no reason given"}", order.Error?.Type);
            if (target == AcmeStatus.Ready && order.Status == AcmeStatus.Valid)
                throw new AcmeException("The order was finalized unexpectedly.");

            await DelayAsync(response.RetryAfter, cancellationToken).ConfigureAwait(false);
        }
    }

    private Task DelayAsync(TimeSpan? retryAfter, CancellationToken cancellationToken)
    {
        var delay = retryAfter ?? DefaultPollInterval;
        if (delay < DefaultPollInterval)
            delay = DefaultPollInterval;
        if (delay > MaxPollInterval)
            delay = MaxPollInterval;
        return Task.Delay(delay, time, cancellationToken);
    }

    /// <summary>
    /// The challenge types to try, in order. TLS-ALPN-01 comes first by default because it only needs the HTTPS
    /// port, which the app is serving anyway; then HTTP-01; then DNS-01, which is slower because of propagation.
    /// A type is skipped if Kestrel isn't listening for it, or, for DNS-01, if no provider is registered.
    /// </summary>
    internal List<string> GetChallengeTypes()
    {
        var addresses = server.Features.Get<IServerAddressesFeature>()?.Addresses ?? [];
        var hasHttps = addresses.Count == 0 || addresses.Any(a => a.StartsWith("https://", StringComparison.OrdinalIgnoreCase));
        var hasHttp = addresses.Count == 0 || addresses.Any(a => a.StartsWith("http://", StringComparison.OrdinalIgnoreCase));

        var types = new List<string>(3);
        if (Options.Challenges.HasFlag(AcmeChallengeTypes.TlsAlpn01) && hasHttps)
            types.Add(AcmeChallenge.TlsAlpn01);
        if (Options.Challenges.HasFlag(AcmeChallengeTypes.Http01) && hasHttp)
            types.Add(AcmeChallenge.Http01);
        if (Options.Challenges.HasFlag(AcmeChallengeTypes.Dns01) && _dns is not null)
            types.Add(AcmeChallenge.Dns01); // Last: it waits for DNS propagation. Wildcards use it regardless.

        // What worked last time first, what failed last time last.
        return types
            .OrderBy(t => t == _lastSucceeded ? 0 : t == _lastFailed ? 2 : 1)
            .ToList();
    }

    private async Task<AccountKey> LoadOrCreateAccountKeyAsync(CancellationToken cancellationToken)
    {
        // One account per certificate authority, so staging and production never share keys.
        var storeKey = AccountKeyKey;

        if (await store.ReadAsync(storeKey, cancellationToken).ConfigureAwait(false) is { } pem)
            return AccountKey.FromPem(Encoding.UTF8.GetString(pem));

        var key = AccountKey.Generate();
        await store.WriteAsync(storeKey, Encoding.UTF8.GetBytes(key.ExportPem()), cancellationToken).ConfigureAwait(false);
        return key;
    }
}
