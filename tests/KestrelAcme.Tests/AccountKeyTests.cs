using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KestrelAcme.Protocol;

namespace KestrelAcme.Tests;

public class AccountKeyTests
{
    private static readonly Uri Url = new("https://ca.example/acme/new-order");

    [Fact]
    public void Signature_verifies_and_header_embeds_the_public_key_before_the_account_exists()
    {
        using var key = AccountKey.Generate();

        var jws = key.Sign("{\"a\":1}"u8, Url, "nonce-1", kid: null);

        Assert.True(key.Verify(jws));
        using var header = JsonDocument.Parse(Base64Url.Decode(jws.Protected));
        var root = header.RootElement;
        Assert.Equal("ES256", root.GetProperty("alg").GetString());
        Assert.Equal("nonce-1", root.GetProperty("nonce").GetString());
        Assert.Equal(Url.AbsoluteUri, root.GetProperty("url").GetString());
        Assert.Equal(key.X, root.GetProperty("jwk").GetProperty("x").GetString());
        Assert.False(root.TryGetProperty("kid", out _));
        Assert.Equal("{\"a\":1}", Encoding.UTF8.GetString(Base64Url.Decode(jws.Payload)));
    }

    [Fact]
    public void Header_uses_the_account_url_once_the_account_exists()
    {
        using var key = AccountKey.Generate();

        var jws = key.Sign([], Url, "nonce-2", kid: "https://ca.example/acct/1");

        using var header = JsonDocument.Parse(Base64Url.Decode(jws.Protected));
        Assert.Equal("https://ca.example/acct/1", header.RootElement.GetProperty("kid").GetString());
        Assert.False(header.RootElement.TryGetProperty("jwk", out _));
        Assert.Equal("", jws.Payload); // POST-as-GET
    }

    [Fact]
    public void Thumbprint_follows_rfc7638()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var key = AccountKey.FromPem(ecdsa.ExportPkcs8PrivateKeyPem());

        var q = ecdsa.ExportParameters(false).Q;
        var canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + Base64Url.Encode(q.X) + "\",\"y\":\"" + Base64Url.Encode(q.Y) + "\"}";
        var expected = Base64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));

        Assert.Equal(expected, key.Thumbprint);
        Assert.Equal($"token.{expected}", key.KeyAuthorization("token"));
    }

    [Fact]
    public void Pem_round_trip_keeps_the_same_key()
    {
        using var key = AccountKey.Generate();
        using var reloaded = AccountKey.FromPem(key.ExportPem());

        Assert.Equal(key.Thumbprint, reloaded.Thumbprint);
        Assert.True(reloaded.Verify(key.Sign("x"u8, Url, "n", null)));
    }

    [Fact]
    public void Rejects_keys_that_are_not_p256()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<CryptographicException>(() => AccountKey.FromPem(p384.ExportPkcs8PrivateKeyPem()));
    }

    [Fact]
    public void External_account_binding_is_an_hmac_signed_copy_of_the_account_key()
    {
        using var key = AccountKey.Generate();
        var hmacKey = RandomNumberGenerator.GetBytes(32);
        var binding = new ExternalAccountBinding("kid-1", Base64Url.Encode(hmacKey));
        var newAccount = new Uri("https://ca.example/acme/new-account");

        var element = key.CreateExternalAccountBinding(binding, newAccount);

        var protectedPart = element.GetProperty("protected").GetString()!;
        var payloadPart = element.GetProperty("payload").GetString()!;
        var expectedSignature = HMACSHA256.HashData(hmacKey, Encoding.ASCII.GetBytes($"{protectedPart}.{payloadPart}"));
        Assert.Equal(Base64Url.Encode(expectedSignature), element.GetProperty("signature").GetString());

        using var header = JsonDocument.Parse(Base64Url.Decode(protectedPart));
        Assert.Equal("HS256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("kid-1", header.RootElement.GetProperty("kid").GetString());
        Assert.Equal(newAccount.AbsoluteUri, header.RootElement.GetProperty("url").GetString());

        using var jwk = JsonDocument.Parse(Base64Url.Decode(payloadPart));
        Assert.Equal(key.X, jwk.RootElement.GetProperty("x").GetString());
        Assert.Equal(key.Y, jwk.RootElement.GetProperty("y").GetString());
    }
}
