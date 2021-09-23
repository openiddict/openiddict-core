/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.Owin;

/// <summary>
/// Exposes the default values used by the OpenIddict server handler.
/// </summary>
public static class OpenIddictServerOwinDefaults
{
    /// <summary>
    /// Default value for <see cref="AuthenticationOptions.AuthenticationType"/>.
    /// </summary>
    public const string AuthenticationType = "OpenIddict.Server.Owin";
}
