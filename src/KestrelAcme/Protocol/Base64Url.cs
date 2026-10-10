using Microsoft.AspNetCore.WebUtilities;

namespace KestrelAcme.Protocol;

/// <summary>Unpadded base64url (RFC 4648 §5), as JOSE and ACME require.</summary>
internal static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data) => WebEncoders.Base64UrlEncode(data);

    public static byte[] Decode(string text) => WebEncoders.Base64UrlDecode(text);

    /// <summary>Accepts base64url and standard base64, padded or not: CAs hand out HMAC keys in both forms.</summary>
    public static bool TryDecodeLenient(string text, out byte[] bytes)
    {
        bytes = [];
        var normalized = text.Trim().Replace('+', '-').Replace('/', '_').TrimEnd('=');
        if (normalized.Length == 0)
            return false;
        try
        {
            bytes = WebEncoders.Base64UrlDecode(normalized);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
