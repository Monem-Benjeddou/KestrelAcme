using System.Text.Json;
using System.Text.Json.Serialization;

namespace KestrelAcme.Protocol;

// Resource shapes from RFC 8555 §7.1 and RFC 9773 (ARI). Only the fields this client uses are mapped.

internal sealed class AcmeDirectory
{
    public required Uri NewNonce { get; init; }
    public required Uri NewAccount { get; init; }
    public required Uri NewOrder { get; init; }
    public Uri? RenewalInfo { get; init; }
    public AcmeDirectoryMeta? Meta { get; init; }
}

internal sealed class AcmeDirectoryMeta
{
    public Uri? TermsOfService { get; init; }
    public bool ExternalAccountRequired { get; init; }
    public Dictionary<string, string>? Profiles { get; init; }
}

internal sealed class AcmeAccount
{
    public string? Status { get; init; }
}

internal static class AcmeStatus
{
    public const string Pending = "pending";
    public const string Ready = "ready";
    public const string Processing = "processing";
    public const string Valid = "valid";
    public const string Invalid = "invalid";
}

internal sealed record AcmeIdentifier(string Type, string Value)
{
    public static AcmeIdentifier Dns(string name) => new("dns", name);
}

internal sealed class AcmeOrder
{
    public required string Status { get; init; }
    public DateTimeOffset? Expires { get; init; }
    public List<AcmeIdentifier> Identifiers { get; init; } = [];
    public List<Uri> Authorizations { get; init; } = [];
    public required Uri Finalize { get; init; }
    public Uri? Certificate { get; init; }
    public AcmeProblem? Error { get; init; }
}

internal sealed class AcmeAuthorization
{
    public required AcmeIdentifier Identifier { get; init; }
    public required string Status { get; init; }
    public List<AcmeChallenge> Challenges { get; init; } = [];
    public bool Wildcard { get; init; }
}

internal sealed class AcmeChallenge
{
    public const string Http01 = "http-01";
    public const string TlsAlpn01 = "tls-alpn-01";

    public required string Type { get; init; }
    public required Uri Url { get; init; }
    public required string Status { get; init; }
    public string? Token { get; init; }
    public AcmeProblem? Error { get; init; }
}

internal sealed class AcmeProblem
{
    public const string BadNonce = "urn:ietf:params:acme:error:badNonce";
    public const string RateLimited = "urn:ietf:params:acme:error:rateLimited";
    public const string AlreadyReplaced = "urn:ietf:params:acme:error:alreadyReplaced";
    public const string Unauthorized = "urn:ietf:params:acme:error:unauthorized";
    public const string AccountDoesNotExist = "urn:ietf:params:acme:error:accountDoesNotExist";

    public string? Type { get; init; }
    public string? Detail { get; init; }
    public int? Status { get; init; }
    public List<AcmeProblem>? Subproblems { get; init; }
    public AcmeIdentifier? Identifier { get; init; }

    public override string ToString()
    {
        var text = $"{Type}: {Detail}";
        if (Subproblems is { Count: > 0 })
            text += " (" + string.Join("; ", Subproblems.Select(p => $"{p.Identifier?.Value}: {p.Detail}")) + ")";
        return text;
    }
}

internal sealed class RenewalInfo
{
    public required RenewalWindow SuggestedWindow { get; init; }

    [JsonPropertyName("explanationURL")]
    public Uri? ExplanationUrl { get; init; }
}

internal sealed record RenewalWindow(DateTimeOffset Start, DateTimeOffset End);

internal sealed class NewAccountRequest
{
    public bool TermsOfServiceAgreed { get; init; }
    public string[]? Contact { get; init; }
    public JsonElement? ExternalAccountBinding { get; init; }
}

internal sealed class NewOrderRequest
{
    public required List<AcmeIdentifier> Identifiers { get; init; }
    public string? Profile { get; init; }
    public string? Replaces { get; init; }
}

internal sealed class FinalizeRequest
{
    public required string Csr { get; init; }
}

internal sealed class EmptyObject;

internal sealed class JwsMessage
{
    public required string Protected { get; init; }
    public required string Payload { get; init; }
    public required string Signature { get; init; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AcmeDirectory))]
[JsonSerializable(typeof(AcmeAccount))]
[JsonSerializable(typeof(AcmeOrder))]
[JsonSerializable(typeof(AcmeAuthorization))]
[JsonSerializable(typeof(AcmeChallenge))]
[JsonSerializable(typeof(AcmeProblem))]
[JsonSerializable(typeof(RenewalInfo))]
[JsonSerializable(typeof(NewAccountRequest))]
[JsonSerializable(typeof(NewOrderRequest))]
[JsonSerializable(typeof(FinalizeRequest))]
[JsonSerializable(typeof(EmptyObject))]
[JsonSerializable(typeof(JwsMessage))]
internal sealed partial class AcmeJsonContext : JsonSerializerContext;
