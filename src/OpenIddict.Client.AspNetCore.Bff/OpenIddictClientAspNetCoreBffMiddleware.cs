/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Enforces the antiforgery header check on BFF API endpoints and rejects anonymous
/// requests sent to YARP routes requiring a user access token.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientAspNetCoreBffMiddleware
{
    private readonly RequestDelegate _next;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientAspNetCoreBffMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline.</param>
    public OpenIddictClientAspNetCoreBffMiddleware(RequestDelegate next)
        => _next = next ?? throw new ArgumentNullException(nameof(next));

    /// <summary>
    /// Processes the request.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var endpoint = context.GetEndpoint();
        if (endpoint is null)
        {
            await _next(context);
            return;
        }

        var metadata = endpoint.Metadata.GetMetadata<OpenIddictClientAspNetCoreBffApiEndpointMetadata>();
        var route = OpenIddictClientAspNetCoreBffHelpers.GetRouteConfig(context)?.Metadata;

        var type = OpenIddictClientAspNetCoreBffTokenType.None;
        var proxied = route is not null && route.TryGetValue(OpenIddictClientAspNetCoreBffConstants.Metadata.AccessToken, out var value) &&
            OpenIddictClientAspNetCoreBffHelpers.TryParseTokenType(value, out type);

        var check = (metadata is { DisableAntiforgeryCheck: false }) || (proxied &&
            !(route!.TryGetValue(OpenIddictClientAspNetCoreBffConstants.Metadata.DisableAntiforgeryCheck, out var disabled) &&
              bool.TryParse(disabled, out var result) && result));

        if (check && !context.HasValidAntiforgeryHeader())
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        if (proxied && type is OpenIddictClientAspNetCoreBffTokenType.User)
        {
            var options = OpenIddictClientAspNetCoreBffHelpers.GetOptions(context);

            var authentication = await context.AuthenticateAsync(options.CookieScheme);
            if (authentication is not { Succeeded: true })
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
        }

        await _next(context);
    }
}
