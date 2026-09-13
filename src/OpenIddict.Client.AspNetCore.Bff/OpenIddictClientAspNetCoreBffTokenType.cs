/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Represents the type of access token attached to requests sent to remote APIs.
/// </summary>
public enum OpenIddictClientAspNetCoreBffTokenType
{
    /// <summary>
    /// No access token is attached.
    /// </summary>
    None = 0,

    /// <summary>
    /// The access token of the authenticated user is attached. Anonymous requests are rejected.
    /// </summary>
    User = 1,

    /// <summary>
    /// The access token of the authenticated user is attached, if available. Anonymous requests are allowed.
    /// </summary>
    OptionalUser = 2,

    /// <summary>
    /// An access token obtained by the client application using the client credentials grant is attached.
    /// </summary>
    Client = 3,

    /// <summary>
    /// The access token of the authenticated user is attached, if available.
    /// Otherwise, an access token obtained using the client credentials grant is attached.
    /// </summary>
    UserOrClient = 4
}
