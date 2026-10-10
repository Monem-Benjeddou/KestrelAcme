namespace KestrelAcme;

/// <summary>The certificate authority rejected a request, or an order could not be completed.</summary>
public sealed class AcmeException : Exception
{
    internal AcmeException(string message, string? problemType = null, int? statusCode = null, TimeSpan? retryAfter = null)
        : base(message)
    {
        ProblemType = problemType;
        StatusCode = statusCode;
        RetryAfter = retryAfter;
    }

    /// <summary>The ACME problem type, such as <c>urn:ietf:params:acme:error:rateLimited</c>, when the server sent one.</summary>
    public string? ProblemType { get; }

    /// <summary>The HTTP status code of the response, when there was one.</summary>
    public int? StatusCode { get; }

    /// <summary>How long the server asked us to wait before trying again, when it said so.</summary>
    public TimeSpan? RetryAfter { get; }
}
