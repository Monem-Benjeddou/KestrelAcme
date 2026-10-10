using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace KestrelAcme.Protocol;

/// <summary>The ACME account key (ECDSA P-256, signs requests as ES256) and the JWS encoding around it (RFC 7515).</summary>
internal sealed class AccountKey : IDisposable
{
    private readonly ECDsa _key;

    private AccountKey(ECDsa key)
    {
        _key = key;
        var parameters = key.ExportParameters(includePrivateParameters: false);
        X = Base64Url.Encode(parameters.Q.X!);
        Y = Base64Url.Encode(parameters.Q.Y!);

        // RFC 7638: the required members, in lexicographic order, without whitespace.
        Thumbprint = Base64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(
            $$"""{"crv":"P-256","kty":"EC","x":"{{X}}","y":"{{Y}}"}""")));
    }

    public string X { get; }
    public string Y { get; }

    /// <summary>JWK thumbprint (RFC 7638), used in challenge key authorizations.</summary>
    public string Thumbprint { get; }

    public static AccountKey Generate() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    public static AccountKey FromPem(string pem)
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(pem);
            if (key.KeySize != 256)
                throw new CryptographicException("The stored ACME account key is not a P-256 key.");
            return new AccountKey(key);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    public string ExportPem() => _key.ExportPkcs8PrivateKeyPem();

    /// <summary>The key authorization for a challenge token (RFC 8555 §8.1).</summary>
    public string KeyAuthorization(string token) => $"{token}.{Thumbprint}";

    /// <summary>Signs a request. Before the account exists, the public key is embedded (<paramref name="kid"/> null).</summary>
    public JwsMessage Sign(ReadOnlySpan<byte> payload, Uri url, string nonce, string? kid)
    {
        var header = WriteJson(w =>
        {
            w.WriteString("alg", "ES256");
            if (kid is null)
            {
                w.WritePropertyName("jwk");
                WriteJwk(w);
            }
            else
            {
                w.WriteString("kid", kid);
            }
            w.WriteString("nonce", nonce);
            w.WriteString("url", url.AbsoluteUri);
        });

        var protectedPart = Base64Url.Encode(header);
        var payloadPart = Base64Url.Encode(payload);
        var signature = _key.SignData(
            Encoding.ASCII.GetBytes($"{protectedPart}.{payloadPart}"),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        return new JwsMessage { Protected = protectedPart, Payload = payloadPart, Signature = Base64Url.Encode(signature) };
    }

    /// <summary>
    /// The <c>externalAccountBinding</c> field of a new-account request (RFC 8555 §7.3.4): this account's public key,
    /// signed with the HMAC key the certificate authority handed out.
    /// </summary>
    public JsonElement CreateExternalAccountBinding(ExternalAccountBinding binding, Uri newAccountUrl)
    {
        var header = WriteJson(w =>
        {
            w.WriteString("alg", "HS256");
            w.WriteString("kid", binding.KeyId);
            w.WriteString("url", newAccountUrl.AbsoluteUri);
        });
        var jwk = WriteJson(WriteJwkMembers);

        var protectedPart = Base64Url.Encode(header);
        var payloadPart = Base64Url.Encode(jwk);
        var signature = HMACSHA256.HashData(
            Base64Url.TryDecodeLenient(binding.HmacKey, out var hmacKey) ? hmacKey : throw new FormatException("Invalid HMAC key."),
            Encoding.ASCII.GetBytes($"{protectedPart}.{payloadPart}"));

        var message = new JwsMessage { Protected = protectedPart, Payload = payloadPart, Signature = Base64Url.Encode(signature) };
        return JsonSerializer.SerializeToElement(message, AcmeJsonContext.Default.JwsMessage);
    }

    public bool Verify(JwsMessage message)
    {
        var signature = Base64Url.Decode(message.Signature);
        return _key.VerifyData(
            Encoding.ASCII.GetBytes($"{message.Protected}.{message.Payload}"),
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private void WriteJwk(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        WriteJwkMembers(writer);
        writer.WriteEndObject();
    }

    private void WriteJwkMembers(Utf8JsonWriter writer)
    {
        writer.WriteString("crv", "P-256");
        writer.WriteString("kty", "EC");
        writer.WriteString("x", X);
        writer.WriteString("y", Y);
    }

    private static byte[] WriteJson(Action<Utf8JsonWriter> writeMembers)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writeMembers(writer);
            writer.WriteEndObject();
        }
        return buffer.WrittenSpan.ToArray();
    }

    public void Dispose() => _key.Dispose();
}
