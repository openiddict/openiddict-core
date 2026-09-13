/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Exposes companion extensions for the OpenIddict backend-for-frontend (BFF) components.
/// </summary>
public static class OpenIddictClientAspNetCoreBffHelpers
{
    /// <summary>
    /// Determines whether the request contains the antiforgery header expected by the BFF components.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns><see langword="true"/> if the antiforgery header is present and valid, <see langword="false"/> otherwise.</returns>
    public static bool HasValidAntiforgeryHeader(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var options = GetOptions(context);

        // Note: requiring a custom header forces cross-origin browsers to send a CORS preflight
        // request, which prevents cross-site request forgery attacks against the BFF endpoints.
        return context.Request.Headers.TryGetValue(options.AntiforgeryHeaderName, out var values) &&
               values.Count is 1 && string.Equals(values[0], options.AntiforgeryHeaderValue, StringComparison.Ordinal);
    }

    /// <summary>
    /// Determines whether the current request targets a BFF API endpoint (i.e a local endpoint marked using
    /// <c>AsOpenIddictBffApiEndpoint()</c> or a YARP route with an OpenIddict BFF access token metadata).
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns><see langword="true"/> if the request targets a BFF API endpoint, <see langword="false"/> otherwise.</returns>
    public static bool IsBffApiRequest(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var endpoint = context.GetEndpoint();
        if (endpoint is null)
        {
            return false;
        }

        return endpoint.Metadata.GetMetadata<OpenIddictClientAspNetCoreBffApiEndpointMetadata>() is not null ||
               GetRouteConfig(context)?.Metadata?.ContainsKey(OpenIddictClientAspNetCoreBffConstants.Metadata.AccessToken) is true;
    }

    /// <summary>
    /// Resolves the YARP route configuration associated with the current request, if applicable.
    /// </summary>
    internal static RouteConfig? GetRouteConfig(HttpContext context)
        => context.GetEndpoint()?.Metadata.GetMetadata<RouteModel>()?.Config;

    /// <summary>
    /// Resolves the BFF options.
    /// </summary>
    internal static OpenIddictClientAspNetCoreBffOptions GetOptions(HttpContext context)
        => context.RequestServices.GetService<IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions>>()?.CurrentValue ??
           throw new InvalidOperationException(SR.GetResourceString(SR.ID0561));

    /// <summary>
    /// Parses the specified BFF access token type.
    /// </summary>
    internal static bool TryParseTokenType(string? value, out OpenIddictClientAspNetCoreBffTokenType type)
    {
        // Note: numeric values are deliberately not accepted.
        if (!string.IsNullOrEmpty(value) && !char.IsDigit(value[0]) && Enum.TryParse(value, ignoreCase: true, out type) &&
            Enum.IsDefined(type))
        {
            return true;
        }

        type = OpenIddictClientAspNetCoreBffTokenType.None;
        return false;
    }

    /// <summary>
    /// Determines whether the specified URL is a local URL (e.g "/path", but not "//host" or "/\host").
    /// </summary>
    internal static bool IsLocalUrl(string? url) => url switch
    {
        null or { Length: 0 } => false,

        // "/" or "/path" but not "//" or "/\".
        ['/'] => true,
        ['/', not ('/' or '\\'), ..] => !ContainsControlCharacters(url),

        // "~/" or "~/path" but not "~//" or "~/\".
        ['~', '/'] => true,
        ['~', '/', not ('/' or '\\'), ..] => !ContainsControlCharacters(url),

        _ => false
    };

    private static bool ContainsControlCharacters(string value) => value.AsSpan().ContainsAnyInRange('\u0000', '\u001f');
}
