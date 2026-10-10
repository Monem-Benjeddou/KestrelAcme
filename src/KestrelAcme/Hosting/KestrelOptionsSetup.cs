using System.Net.Security;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace KestrelAcme.Hosting;

/// <summary>
/// Plugs into every Kestrel endpoint: a connection middleware reads the ClientHello, then the HTTPS defaults
/// pick the certificate in <c>OnAuthenticate</c>, using a certificate context so the full chain is sent.
/// </summary>
/// <remarks>
/// The placeholder certificate is set as the default HTTPS certificate. An endpoint whose certificate is still the
/// placeholder at handshake time gets the ACME certificate; endpoints that configured their own are left alone.
/// </remarks>
internal sealed class KestrelOptionsSetup(
    CertificateSelector selector,
    ChallengeResponder challenges,
    ILogger<KestrelOptionsSetup> logger) : IConfigureOptions<KestrelServerOptions>
{
    private static readonly List<SslApplicationProtocol> AcmeTlsOnly = [new(ChallengeResponder.AcmeTlsProtocol)];

    public void Configure(KestrelServerOptions options)
    {
        options.ConfigureEndpointDefaults(listen =>
            listen.Use(next => new ClientHelloMiddleware(next, logger).InvokeAsync));

        options.ConfigureHttpsDefaults(https =>
        {
            https.ServerCertificate = selector.Placeholder.Leaf;
            https.OnAuthenticate += (connection, ssl) => OnAuthenticate(connection, ssl);
        });
    }

    internal void OnAuthenticate(ConnectionContext connection, SslServerAuthenticationOptions ssl)
    {
        var clientHello = connection.Features.Get<ClientHello>();

        // RFC 8737: a validation connection offers only acme-tls/1 and must get the challenge certificate.
        if (clientHello?.Offers(ChallengeResponder.AcmeTlsProtocol) == true
            && challenges.TryGetTlsAlpn01(clientHello.ServerName, out var challenge))
        {
            Log.TlsAlpnChallengeServed(logger, clientHello.ServerName!);
            UseCertificate(ssl, challenge.Context);
            ssl.ApplicationProtocols = AcmeTlsOnly;
            return;
        }

        if (!selector.IsPlaceholder(ssl.ServerCertificateContext?.TargetCertificate ?? ssl.ServerCertificate))
            return;

        UseCertificate(ssl, selector.Current.Context);
    }

    private static void UseCertificate(SslServerAuthenticationOptions ssl, SslStreamCertificateContext context)
    {
        ssl.ServerCertificate = null;
        ssl.ServerCertificateSelectionCallback = null;
        ssl.ServerCertificateContext = context;
    }
}
