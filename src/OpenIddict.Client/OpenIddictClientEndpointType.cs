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
    PostLogoutRedirection = 2,

    /// <summary>
    /// Back-channel logout endpoint (OpenID Connect Back-Channel Logout 1.0).
    /// </summary>
    BackchannelLogout = 3,

    /// <summary>
    /// Front-channel logout endpoint (OpenID Connect Front-Channel Logout 1.0).
    /// </summary>
    FrontchannelLogout = 4
}
