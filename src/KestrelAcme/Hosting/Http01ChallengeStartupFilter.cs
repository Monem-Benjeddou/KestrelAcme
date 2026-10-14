using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace KestrelAcme.Hosting;

/// <summary>
/// Answers HTTP-01 challenges (RFC 8555 §8.3) ahead of the app's own middleware, so HTTPS redirection,
/// authentication or routing can't get in the way. Tokens of another instance's order are answered from the store;
/// unknown tokens fall through to the app.
/// </summary>
internal sealed class Http01ChallengeStartupFilter(ChallengeResponder challenges, ILogger<Http01ChallengeStartupFilter> logger) : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, nextMiddleware) =>
        {
            var request = context.Request;
            if (HttpMethods.IsGet(request.Method)
                && request.Path.StartsWithSegments(ChallengeResponder.Http01PathPrefix.TrimEnd('/'), out var rest)
                && rest.Value is { Length: > 1 } tokenPath
                && await challenges.FindHttp01Async(tokenPath[1..], context.RequestAborted).ConfigureAwait(false) is { } keyAuthorization)
            {
                Log.Http01ChallengeServed(logger, request.Host.Host);
                context.Response.ContentType = "application/octet-stream";
                await context.Response.WriteAsync(keyAuthorization, context.RequestAborted).ConfigureAwait(false);
                return;
            }

            await nextMiddleware(context).ConfigureAwait(false);
        });

        next(app);
    };
}
