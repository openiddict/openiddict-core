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
