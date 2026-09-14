/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.Saml.AspNetCore;

/// <summary>
/// Exposes the default values used by the OpenIddict SAML 2.0 service provider ASP.NET Core integration.
/// </summary>
public static class OpenIddictClientSamlAspNetCoreDefaults
{
    /// <summary>
    /// Default value for <see cref="AuthenticationScheme.Name"/>.
    /// </summary>
    public const string AuthenticationScheme = "OpenIddict.Client.Saml.AspNetCore";
}
