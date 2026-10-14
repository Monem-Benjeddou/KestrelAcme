using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using KestrelAcme.Diagnostics;
using Microsoft.Extensions.Logging;

namespace KestrelAcme.Protocol;

/// <summary>A response body together with the headers ACME puts meaning in.</summary>
internal sealed record AcmeResponse<T>(T Value, Uri? Location, TimeSpan? RetryAfter);

/// <summary>Minimal RFC 8555 client: one account, the calls needed to order a certificate, and ARI.</summary>
internal sealed class AcmeClient
{
    private const int MaxBadNonceRetries = 5;
    private static readonly MediaTypeHeaderValue JoseJson = new("application/jose+json");

    private readonly Func<HttpClient> _createHttp;
    private readonly Uri _directoryUri;
    private readonly AccountKey _key;
    private readonly ILogger _logger;
    private readonly ConcurrentBag<string> _nonces = [];
    private AcmeDirectory? _directory;

    public AcmeClient(Func<HttpClient> createHttp, Uri directoryUri, AccountKey key, ILogger logger)
    {
        // A client per request, from IHttpClientFactory, so handlers are recycled and DNS changes are seen.
        _createHttp = createHttp;
        _directoryUri = directoryUri;
        _key = key;
        _logger = logger;
    }

    public AccountKey Key => _key;

    /// <summary>The account URL, which signs every request once the account exists.</summary>
    public string? AccountUrl { get; private set; }

    public async Task<AcmeDirectory> GetDirectoryAsync(CancellationToken cancellationToken)
    {
        if (_directory is not null)
            return _directory;

        using var activity = AcmeDiagnostics.StartActivity("directory", _directoryUri);
        using var response = await _createHttp().GetAsync(_directoryUri, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        _directory = await ReadAsync(response, AcmeJsonContext.Default.AcmeDirectory, cancellationToken).ConfigureAwait(false);
        return _directory;
    }

    /// <summary>Creates the account, or finds the existing one for this key (the server answers 200 instead of 201).</summary>
    public async Task<AcmeAccount> CreateAccountAsync(
        string? email, bool termsOfServiceAgreed, ExternalAccountBinding? binding, CancellationToken cancellationToken)
    {
        var directory = await GetDirectoryAsync(cancellationToken).ConfigureAwait(false);

        if (directory.Meta?.ExternalAccountRequired == true && binding is null)
            throw new AcmeException(
                "This certificate authority requires external account binding. Set AcmeOptions.ExternalAccountBinding.");

        var request = new NewAccountRequest
        {
            TermsOfServiceAgreed = termsOfServiceAgreed,
            Contact = email is null ? null : [$"mailto:{email}"],
            ExternalAccountBinding = binding is null ? null : _key.CreateExternalAccountBinding(binding, directory.NewAccount),
        };

        var response = await PostAsync(
            directory.NewAccount,
            Serialize(request, AcmeJsonContext.Default.NewAccountRequest),
            AcmeJsonContext.Default.AcmeAccount,
            useKid: false,
            cancellationToken).ConfigureAwait(false);

        AccountUrl = response.Location?.AbsoluteUri
            ?? throw new AcmeException("The certificate authority did not return an account URL.");
        return response.Value;
    }

    public async Task<AcmeResponse<AcmeOrder>> NewOrderAsync(
        IEnumerable<string> domains, string? profile, string? replaces, CancellationToken cancellationToken)
    {
        var directory = await GetDirectoryAsync(cancellationToken).ConfigureAwait(false);
        var request = new NewOrderRequest
        {
            Identifiers = domains.Select(AcmeIdentifier.Dns).ToList(),
            Profile = profile,
            Replaces = replaces,
        };
        return await PostAsync(
            directory.NewOrder,
            Serialize(request, AcmeJsonContext.Default.NewOrderRequest),
            AcmeJsonContext.Default.AcmeOrder,
            useKid: true,
            cancellationToken).ConfigureAwait(false);
    }

    public Task<AcmeResponse<AcmeOrder>> GetOrderAsync(Uri url, CancellationToken cancellationToken) =>
        PostAsGetAsync(url, AcmeJsonContext.Default.AcmeOrder, cancellationToken);

    public Task<AcmeResponse<AcmeAuthorization>> GetAuthorizationAsync(Uri url, CancellationToken cancellationToken) =>
        PostAsGetAsync(url, AcmeJsonContext.Default.AcmeAuthorization, cancellationToken);

    /// <summary>Tells the server the challenge response is in place (RFC 8555 §7.5.1).</summary>
    public Task<AcmeResponse<AcmeChallenge>> AnswerChallengeAsync(Uri url, CancellationToken cancellationToken) =>
        PostAsync(url, "{}"u8.ToArray(), AcmeJsonContext.Default.AcmeChallenge, useKid: true, cancellationToken);

    public Task<AcmeResponse<AcmeOrder>> FinalizeAsync(Uri url, byte[] csrDer, CancellationToken cancellationToken) =>
        PostAsync(
            url,
            Serialize(new FinalizeRequest { Csr = Base64Url.Encode(csrDer) }, AcmeJsonContext.Default.FinalizeRequest),
            AcmeJsonContext.Default.AcmeOrder,
            useKid: true,
            cancellationToken);

    /// <summary>Downloads the issued certificate and its chain as PEM.</summary>
    public async Task<string> DownloadCertificateAsync(Uri url, CancellationToken cancellationToken)
    {
        using var response = await SendSignedAsync(url, [], useKid: true, cancellationToken).ConfigureAwait(false);
        return await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The certificate authority's suggested renewal window (RFC 9773). Returns null when the server has no
    /// ARI endpoint or doesn't know the certificate.
    /// </summary>
    public async Task<AcmeResponse<RenewalInfo>?> GetRenewalInfoAsync(string certificateId, CancellationToken cancellationToken)
    {
        var directory = await GetDirectoryAsync(cancellationToken).ConfigureAwait(false);
        if (directory.RenewalInfo is null)
            return null;

        var url = new Uri(directory.RenewalInfo.AbsoluteUri.TrimEnd('/') + "/" + certificateId);
        using var activity = AcmeDiagnostics.StartActivity("renewalInfo", FromCa(url));
        using var response = await _createHttp().GetAsync(url, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;

        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        var info = await ReadAsync(response, AcmeJsonContext.Default.RenewalInfo, cancellationToken).ConfigureAwait(false);
        return new AcmeResponse<RenewalInfo>(info, null, GetRetryAfter(response));
    }

    private Task<AcmeResponse<T>> PostAsGetAsync<T>(Uri url, JsonTypeInfo<T> type, CancellationToken cancellationToken) =>
        PostAsync(url, [], type, useKid: true, cancellationToken);

    private async Task<AcmeResponse<T>> PostAsync<T>(
        Uri url, byte[] payload, JsonTypeInfo<T> type, bool useKid, CancellationToken cancellationToken)
    {
        using var response = await SendSignedAsync(url, payload, useKid, cancellationToken).ConfigureAwait(false);
        var value = await ReadAsync(response, type, cancellationToken).ConfigureAwait(false);
        return new AcmeResponse<T>(value, response.Headers.Location, GetRetryAfter(response));
    }

    private async Task<HttpResponseMessage> SendSignedAsync(
        Uri url, byte[] payload, bool useKid, CancellationToken cancellationToken)
    {
        if (useKid && AccountUrl is null)
            throw new InvalidOperationException("Create the account before sending account-signed requests.");

        using var activity = AcmeDiagnostics.StartActivity("post", FromCa(url));

        for (var attempt = 1; ; attempt++)
        {
            var nonce = await TakeNonceAsync(cancellationToken).ConfigureAwait(false);
            var jws = _key.Sign(payload, url, nonce, useKid ? AccountUrl : null);

            var content = new ByteArrayContent(Serialize(jws, AcmeJsonContext.Default.JwsMessage));
            content.Headers.ContentType = JoseJson;

            var response = await _createHttp().PostAsync(url, content, cancellationToken).ConfigureAwait(false);
            KeepNonce(response);

            if (response.IsSuccessStatusCode)
                return response;

            try
            {
                var problem = await ReadProblemAsync(response, cancellationToken).ConfigureAwait(false);

                // RFC 8555 §6.5: a rejected nonce is expected now and then; retry with the fresh one we just got.
                if (problem?.Type == AcmeProblem.BadNonce && attempt < MaxBadNonceRetries)
                {
                    Log.BadNonce(_logger, url, attempt);
                    continue;
                }

                throw CreateException(response, problem);
            }
            finally
            {
                response.Dispose();
            }
        }
    }

    /// <summary>A URL the CA supplied. Only https: a hostile directory must not point requests at internal services.</summary>
    private static Uri FromCa(Uri url) =>
        url.Scheme == Uri.UriSchemeHttps ? url : throw new AcmeException($"The certificate authority gave a non-HTTPS URL: {url}");

    private async ValueTask<string> TakeNonceAsync(CancellationToken cancellationToken)
    {
        if (_nonces.TryTake(out var nonce))
            return nonce;

        var directory = await GetDirectoryAsync(cancellationToken).ConfigureAwait(false);
        using var request = new HttpRequestMessage(HttpMethod.Head, FromCa(directory.NewNonce));
        using var response = await _createHttp().SendAsync(request, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);

        return response.Headers.TryGetValues("Replay-Nonce", out var values) && values.FirstOrDefault() is { } fresh
            ? fresh
            : throw new AcmeException("The certificate authority did not return a nonce.");
    }

    private void KeepNonce(HttpResponseMessage response)
    {
        if (response.Headers.TryGetValues("Replay-Nonce", out var values) && values.FirstOrDefault() is { } nonce)
            _nonces.Add(nonce);
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode)
            throw CreateException(response, await ReadProblemAsync(response, cancellationToken).ConfigureAwait(false));
    }

    private static AcmeException CreateException(HttpResponseMessage response, AcmeProblem? problem)
    {
        var request = response.RequestMessage;
        var message = problem is null
            ? $"{request?.Method} {request?.RequestUri} failed with HTTP {(int)response.StatusCode}."
            : $"{request?.Method} {request?.RequestUri} failed with HTTP {(int)response.StatusCode}: {problem}";
        return new AcmeException(message, problem?.Type, (int)response.StatusCode, GetRetryAfter(response));
    }

    private static async Task<AcmeProblem?> ReadProblemAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentType?.MediaType is not ("application/problem+json" or "application/json"))
            return null;

        try
        {
            return await ReadAsync(response, AcmeJsonContext.Default.AcmeProblem, cancellationToken).ConfigureAwait(false);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static async Task<T> ReadAsync<T>(HttpResponseMessage response, JsonTypeInfo<T> type, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync(stream, type, cancellationToken).ConfigureAwait(false)
            ?? throw new AcmeException($"Empty response from {response.RequestMessage?.RequestUri}.");
    }

    private static TimeSpan? GetRetryAfter(HttpResponseMessage response)
    {
        var retryAfter = response.Headers.RetryAfter;
        if (retryAfter?.Delta is { } delta)
            return delta;
        if (retryAfter?.Date is { } date)
        {
            var wait = date - DateTimeOffset.UtcNow;
            return wait > TimeSpan.Zero ? wait : TimeSpan.Zero;
        }
        return null;
    }

    private static byte[] Serialize<T>(T value, JsonTypeInfo<T> type) => JsonSerializer.SerializeToUtf8Bytes(value, type);
}
