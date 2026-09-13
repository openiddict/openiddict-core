/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using static OpenIddict.Server.Saml.OpenIddictServerSamlModels;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Creates the subject, authentication statement and attributes of the assertions issued to service providers.
/// </summary>
/// <remarks>Implementations are resolved from the request services and can be registered with any lifetime.</remarks>
public interface IOpenIddictServerSamlAssertionProvider
{
    /// <summary>
    /// Creates the assertion descriptor corresponding to the authenticated user.
    /// </summary>
    /// <param name="context">The assertion context.</param>
    /// <returns>
    /// The assertion descriptor, or <see langword="null"/> to deny the request
    /// (in which case a RequestDenied response is returned to the service provider).
    /// </returns>
    ValueTask<AssertionDescriptor?> CreateAssertionAsync(AssertionContext context);
}
