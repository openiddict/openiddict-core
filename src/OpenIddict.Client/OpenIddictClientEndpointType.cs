/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client;

/// <summary>
/// Represents the type of an OpenIddict client endpoint.
/// </summary>
public enum OpenIddictClientEndpointType
{
    /// <summary>
    /// Unknown endpoint.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Redirection endpoint.
    /// </summary>
    Redirection = 1,

    /// <summary>
    /// Post-logout redirection endpoint.
    /// </summary>
    PostLogoutRedirection = 2
}
