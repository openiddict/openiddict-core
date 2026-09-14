/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server;

/// <summary>
/// Represents the type of an operation performed using the dynamic client registration endpoint.
/// </summary>
public enum OpenIddictServerRegistrationRequestType
{
    /// <summary>
    /// Unknown operation (e.g unsupported HTTP method).
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Client registration request (RFC 7591, HTTP POST).
    /// </summary>
    Registration = 1,

    /// <summary>
    /// Client read request (RFC 7592, HTTP GET).
    /// </summary>
    Read = 2,

    /// <summary>
    /// Client update request (RFC 7592, HTTP PUT).
    /// </summary>
    Update = 3,

    /// <summary>
    /// Client delete request (RFC 7592, HTTP DELETE).
    /// </summary>
    Deletion = 4
}
