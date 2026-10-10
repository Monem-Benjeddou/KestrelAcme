using Microsoft.Extensions.Options;

namespace KestrelAcme;

internal sealed class AcmeOptionsValidator(IEnumerable<IDnsChallengeProvider> dnsProviders) : IValidateOptions<AcmeOptions>
{
    public AcmeOptionsValidator()
        : this([])
    {
    }

    public ValidateOptionsResult Validate(string? name, AcmeOptions options)
    {
        var canUseDns = options.Challenges.HasFlag(AcmeChallengeTypes.Dns01) && dnsProviders.Any();
        var errors = new List<string>();

        if (options.Domains.Count == 0)
            errors.Add("At least one domain is required (AcmeOptions.Domains).");

        foreach (var domain in options.Domains)
        {
            if (!IsValidDomain(domain))
                errors.Add($"'{domain}' is not a valid domain name.");
            else if (domain.StartsWith("*.", StringComparison.Ordinal) && !canUseDns)
                errors.Add($"'{domain}': wildcard names can only be validated with DNS-01. Register an IDnsChallengeProvider "
                    + "and keep AcmeChallengeTypes.Dns01 enabled.");
        }

        if (!options.AcceptTermsOfService)
            errors.Add("Set AcmeOptions.AcceptTermsOfService = true to accept the certificate authority's terms of service.");

        if (!options.DirectoryUri.IsAbsoluteUri || options.DirectoryUri.Scheme != Uri.UriSchemeHttps)
            errors.Add("AcmeOptions.DirectoryUri must be an absolute https URL.");

        if (options.Challenges == AcmeChallengeTypes.None)
            errors.Add("Enable at least one challenge type (AcmeOptions.Challenges).");

        if (options.Email is { } email && (email.Length == 0 || email.Contains(':') || !email.Contains('@')))
            errors.Add($"'{email}' is not a valid email address.");

        if (options.RenewBefore is { } renewBefore && renewBefore <= TimeSpan.Zero)
            errors.Add("AcmeOptions.RenewBefore must be positive.");

        if (options.DnsPropagationDelay < TimeSpan.Zero)
            errors.Add("AcmeOptions.DnsPropagationDelay can't be negative.");

        if (options.IssuanceTimeout <= TimeSpan.Zero)
            errors.Add("AcmeOptions.IssuanceTimeout must be positive.");

        if (options.ExternalAccountBinding is { } eab &&
            (string.IsNullOrWhiteSpace(eab.KeyId) || string.IsNullOrWhiteSpace(eab.HmacKey)))
            errors.Add("ExternalAccountBinding needs both KeyId and HmacKey.");
        else if (options.ExternalAccountBinding is { } binding && !Protocol.Base64Url.TryDecodeLenient(binding.HmacKey, out _))
            errors.Add("ExternalAccountBinding.HmacKey is not valid base64 or base64url.");

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }

    internal static bool IsValidDomain(string domain)
    {
        var name = domain.StartsWith("*.", StringComparison.Ordinal) ? domain[2..] : domain;
        return name.Length is > 0 and <= 253
            && !name.EndsWith('.')
            && Uri.CheckHostName(name) == UriHostNameType.Dns;
    }
}
