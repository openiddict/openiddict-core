/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using OpenIddict.Server.Saml.Owin;

namespace Owin;

/// <summary>
/// Exposes companion extensions for the OpenIddict SAML 2.0 identity provider OWIN/Katana integration.
/// </summary>
public static class OpenIddictServerSamlOwinHelpers
{
    /// <summary>
    /// Registers the OpenIddict SAML 2.0 identity provider OWIN middleware (metadata and single sign-on endpoints)
    /// in the application pipeline. The middleware must be registered after the authentication middleware
    /// and requires the scoped <see cref="IServiceProvider"/> to be attached to the OWIN context.
    /// </summary>
    /// <param name="app">The application builder used to register middleware instances.</param>
    /// <returns>The <see cref="IAppBuilder"/> instance.</returns>
    public static IAppBuilder UseOpenIddictSaml(this IAppBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.Use<OpenIddictServerSamlOwinMiddleware>();
    }
}
