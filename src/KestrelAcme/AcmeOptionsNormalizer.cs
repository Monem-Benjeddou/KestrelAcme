using System.Globalization;
using Microsoft.Extensions.Options;

namespace KestrelAcme;

/// <summary>
/// Puts domains in the form the CA and certificates use: lower case, internationalized names in punycode
/// (<c>bücher.example</c> becomes <c>xn--bcher-kva.example</c>), no duplicates.
/// </summary>
internal sealed class AcmeOptionsNormalizer : IPostConfigureOptions<AcmeOptions>
{
    private static readonly IdnMapping Idn = new();

    public void PostConfigure(string? name, AcmeOptions options)
    {
        var normalized = options.Domains
            .Select(Normalize)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        options.Domains.Clear();
        foreach (var domain in normalized)
            options.Domains.Add(domain);
    }

    internal static string Normalize(string domain)
    {
        var trimmed = domain.Trim();
        var wildcard = trimmed.StartsWith("*.", StringComparison.Ordinal);
        try
        {
            var ascii = Idn.GetAscii(wildcard ? trimmed[2..] : trimmed).ToLowerInvariant();
            return wildcard ? "*." + ascii : ascii;
        }
        catch (ArgumentException)
        {
            return trimmed.ToLowerInvariant(); // Not a valid name; the validator reports it.
        }
    }
}
