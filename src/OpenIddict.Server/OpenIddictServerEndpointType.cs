/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server;

/// <summary>
/// Represents the type of an OpenIddict server endpoint.
/// </summary>
public enum OpenIddictServerEndpointType
{
    /// <summary>
    /// Unknown endpoint.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Authorization endpoint.
    /// </summary>
    Authorization = 1,

    /// <summary>
    /// Token endpoint.
    /// </summary>
    Token = 2,

    /// <summary>
    /// Logout endpoint.
    /// </summary>
    Logout = 3,

    /// <summary>
    /// Configuration endpoint.
    /// </summary>
    Configuration = 4,

    /// <summary>
    /// Cryptography endpoint.
    /// </summary>
    Cryptography = 5,

    /// <summary>
    /// Userinfo endpoint.
    /// </summary>
    Userinfo = 6,

    /// <summary>
    /// Introspection endpoint.
    /// </summary>
    Introspection = 7,

    /// <summary>
    /// Revocation endpoint.
    /// </summary>
    Revocation = 8,

    /// <summary>
    /// Device endpoint.
    /// </summary>
    Device = 9,

    /// <summary>
    /// Verification endpoint.
    /// </summary>
    Verification = 10
}
