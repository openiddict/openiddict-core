/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.Owin;

/// <summary>
/// Exposes the default values used by the OpenIddict client handler.
/// </summary>
public static class OpenIddictClientOwinDefaults
{
    /// <summary>
    /// Default value for <see cref="AuthenticationOptions.AuthenticationType"/>.
    /// </summary>
    public const string AuthenticationType = "OpenIddict.Client.Owin";
}
