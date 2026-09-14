/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using OpenIddict.Client.Saml.Owin;
using static OpenIddict.Client.Saml.OpenIddictClientSamlModels;

namespace Owin;

/// <summary>
/// Exposes companion extensions for the OpenIddict SAML 2.0 service provider OWIN/Katana integration.
/// </summary>
public static class OpenIddictClientSamlOwinHelpers
{
    /// <summary>
    /// Registers the OpenIddict SAML 2.0 service provider OWIN middleware (challenges, assertion consumer service
    /// and metadata endpoints) in the application pipeline. The middleware must be registered after the
    /// authentication middleware used to sign the user in and requires the scoped <see cref="IServiceProvider"/>
    /// to be attached to the OWIN context.
    /// </summary>
    /// <param name="app">The application builder used to register middleware instances.</param>
    /// <returns>The <see cref="IAppBuilder"/> instance.</returns>
    public static IAppBuilder UseOpenIddictClientSaml(this IAppBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.Use<OpenIddictClientSamlOwinMiddleware>();
    }

    /// <summary>
    /// Retrieves the validation result of the SAML response received by the assertion consumer service, if applicable.
    /// </summary>
    /// <param name="context">The OWIN context.</param>
    /// <returns>The validation result, or <see langword="null"/> if no SAML response was validated.</returns>
    public static ResponseValidationResult? GetOpenIddictClientSamlResponse(this IOwinContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Get<ResponseValidationResult>(typeof(ResponseValidationResult).FullName);
    }
}
