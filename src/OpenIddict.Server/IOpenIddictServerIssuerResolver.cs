/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server;

/// <summary>
/// Resolves the issuer that must be used to process a request when issuer resolution
/// is enabled (i.e when a single server instance serves multiple issuers).
/// </summary>
/// <remarks>
/// The resolved issuer is used as the base URI of the request: relative endpoint URIs are resolved relatively
/// to it, the discovery document advertises it and tokens are issued for and validated against it.
/// As such, the returned issuer must share the scheme, host and port of the request URI and the request path
/// must be located under the issuer path, otherwise no endpoint is matched. When the server is hosted behind
/// a reverse proxy, the forwarded headers must be applied (e.g using the ASP.NET Core forwarded headers
/// middleware) before OpenIddict processes the request so that the request URI reflects the public address.
/// </remarks>
public interface IOpenIddictServerIssuerResolver
{
    /// <summary>
    /// Resolves the issuer that must be used to process the current request.
    /// </summary>
    /// <param name="context">The issuer resolution context.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation, whose result returns
    /// the absolute issuer URI (without query string or fragment) or <see langword="null"/> if the request doesn't
    /// belong to any known issuer, in which case the request is not handled by the OpenIddict server.
    /// </returns>
    ValueTask<Uri?> ResolveIssuerAsync(OpenIddictServerIssuerResolutionContext context);
}
