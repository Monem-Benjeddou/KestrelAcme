using KestrelAcme.Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;

namespace KestrelAcme.Hosting;

/// <summary>
/// Kestrel connection middleware that runs before TLS: it looks at the ClientHello without consuming it and
/// stores the result as a connection feature, for <see cref="KestrelOptionsSetup"/> to pick the certificate.
/// </summary>
internal sealed class ClientHelloMiddleware(ConnectionDelegate next, ChallengeResponder challenges, ILogger logger)
{
    private static readonly TimeSpan PeekTimeout = TimeSpan.FromSeconds(5);

    public async Task InvokeAsync(ConnectionContext connection)
    {
        if (await PeekAsync(connection).ConfigureAwait(false) is not { } clientHello)
        {
            await next(connection).ConfigureAwait(false);
            return;
        }

        connection.Features.Set(clientHello);

        // A TLS-ALPN-01 validation for another instance's order. OnAuthenticate can't wait for the store, so the
        // challenge certificate is loaded here. It is owned by ChallengeResponder, not this connection.
        var shared = clientHello.Offers(ChallengeResponder.AcmeTlsProtocol) && clientHello.ServerName is { } name
            && !challenges.TryGetTlsAlpn01(name, out _)
            ? await challenges.LoadSharedTlsAlpn01Async(name, connection.ConnectionClosed).ConfigureAwait(false)
            : null;
        if (shared is not null)
            connection.Features.Set(new SharedTlsAlpn01Challenge(shared));

        await next(connection).ConfigureAwait(false);
    }

    private async Task<ClientHello?> PeekAsync(ConnectionContext connection)
    {
        var input = connection.Transport.Input;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(connection.ConnectionClosed);
        timeout.CancelAfter(PeekTimeout);

        try
        {
            while (true)
            {
                var result = await input.ReadAsync(timeout.Token).ConfigureAwait(false);
                var buffer = result.Buffer;
                var status = ClientHelloParser.TryParse(buffer, out var clientHello);

                if (status == ClientHelloParseResult.Incomplete
                    && !result.IsCompleted
                    && buffer.Length < ClientHelloParser.MaxClientHelloLength)
                {
                    // Nothing consumed, everything examined: the next read waits for more bytes.
                    input.AdvanceTo(buffer.Start, buffer.End);
                    continue;
                }

                // Nothing consumed or examined: the TLS layer reads the same bytes again, straight away.
                input.AdvanceTo(buffer.Start);
                return status == ClientHelloParseResult.Success ? clientHello : null;
            }
        }
        catch (OperationCanceledException)
        {
            // The client was slow or went away. Let the TLS layer deal with it as usual.
            return null;
        }
        catch (Exception e)
        {
            Log.ClientHelloPeekFailed(logger, connection.ConnectionId, e);
            return null;
        }
    }
}

/// <summary>The TLS-ALPN-01 certificate for a connection validating another instance's order.</summary>
internal sealed record SharedTlsAlpn01Challenge(CertificateBundle Certificate);
