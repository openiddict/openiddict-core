/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;

namespace OpenIddict.Server;

/// <summary>
/// Exposes the logic used to resolve the issuer of a request when issuer resolution is enabled
/// (i.e when a single server instance serves multiple issuers). This class is used by the server
/// stack and by the validation/server integration, so that both always agree on the issuer.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictServerIssuerResolution
{
    /// <summary>
    /// Resolves the issuer of the current request using the registered <see cref="IOpenIddictServerIssuerResolver"/>
    /// or, if no custom resolver was registered, using the issuers listed in <see cref="OpenIddictServerOptions.Issuers"/>.
    /// </summary>
    /// <param name="context">The issuer resolution context.</param>
    /// <returns>The resolved issuer or <see langword="null"/> if no issuer matches the request.</returns>
    /// <exception cref="InvalidOperationException">No issuer source is configured or the resolved issuer is invalid.</exception>
    public static async ValueTask<Uri?> ResolveIssuerAsync(OpenIddictServerIssuerResolutionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        Uri? issuer;

        if (context.ServiceProvider.GetService<IOpenIddictServerIssuerResolver>() is IOpenIddictServerIssuerResolver resolver)
        {
            issuer = await resolver.ResolveIssuerAsync(context);
        }

        else if (context.Options.Issuers.Count is 0)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0929));
        }

        else
        {
            issuer = MatchIssuer(context.Options.Issuers, context.RequestUri);
        }

        if (issuer is not null && !IsValidIssuer(issuer))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0925));
        }

        return issuer;
    }

    /// <summary>
    /// Returns the issuer whose URI is the most specific base of the request URI: the scheme, the host and the port
    /// must be identical and the issuer path must be a prefix of the request path ending at a segment boundary
    /// (e.g "https://contoso.com/tenant1" matches "https://contoso.com/tenant1/connect/token" but not
    /// "https://contoso.com/tenant10/connect/token"). Path comparisons are case-insensitive, like endpoint URIs.
    /// </summary>
    /// <param name="issuers">The candidate issuers.</param>
    /// <param name="uri">The absolute request URI.</param>
    /// <returns>The matching issuer, or <see langword="null"/> if no issuer matches.</returns>
    public static Uri? MatchIssuer(IEnumerable<Uri> issuers, Uri uri)
    {
        ArgumentNullException.ThrowIfNull(issuers);
        ArgumentNullException.ThrowIfNull(uri);

        if (!uri.IsAbsoluteUri)
        {
            return null;
        }

        Uri? result = null;
        var length = -1;

        foreach (var issuer in issuers)
        {
            if (issuer is not { IsAbsoluteUri: true } ||
                !string.Equals(issuer.Scheme, uri.Scheme, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(issuer.Host, uri.Host, StringComparison.OrdinalIgnoreCase) || issuer.Port != uri.Port)
            {
                continue;
            }

            var path = issuer.AbsolutePath.TrimEnd('/');
            if (path.Length is not 0 && !string.Equals(uri.AbsolutePath, path, StringComparison.OrdinalIgnoreCase) &&
                !uri.AbsolutePath.StartsWith(path + "/", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (path.Length > length)
            {
                (result, length) = (issuer, path.Length);
            }
        }

        return result;
    }

    /// <summary>
    /// Determines whether the specified principal, extracted from a token issued by the server, was issued by the
    /// specified issuer. The private "oi_iss" claim is used if present, the standard "iss" claim otherwise.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="issuer">The expected issuer.</param>
    /// <returns><see langword="true"/> if the principal was issued by the issuer, <see langword="false"/> otherwise.</returns>
    public static bool IsIssuedBy(ClaimsPrincipal principal, Uri issuer)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(issuer);

        var value = principal.GetClaim(Claims.Private.Issuer) ?? principal.GetClaim(Claims.Issuer);

        // Note: the issuer is always attached using Uri.AbsoluteUri when tokens are created. Comparing the
        // normalized representations allows "https://contoso.com" and "https://contoso.com/" to be considered
        // equivalent (RFC 3986, section 6.2.3) while paths, query strings and fragments must be identical.
        return !string.IsNullOrEmpty(value) && issuer.IsAbsoluteUri &&
            Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) &&
            string.Equals(uri.AbsoluteUri, issuer.AbsoluteUri, StringComparison.Ordinal);
    }

    /// <summary>
    /// Determines whether the specified URI can be used as an issuer: it must be an absolute
    /// URI that doesn't contain a query string or a fragment (OpenID Connect Discovery, section 3).
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <returns><see langword="true"/> if the URI is a valid issuer, <see langword="false"/> otherwise.</returns>
    public static bool IsValidIssuer(Uri issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);

        return issuer.IsAbsoluteUri && !OpenIddictHelpers.IsImplicitFileUri(issuer) &&
            string.IsNullOrEmpty(issuer.Query) && string.IsNullOrEmpty(issuer.Fragment);
    }
}
