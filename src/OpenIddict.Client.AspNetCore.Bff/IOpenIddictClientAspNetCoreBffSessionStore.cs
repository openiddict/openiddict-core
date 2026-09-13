/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Authentication.Cookies;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Represents a server-side session store (<see cref="ITicketStore"/>) that supports removing
/// sessions when a back-channel logout notification is received from an authorization server.
/// </summary>
public interface IOpenIddictClientAspNetCoreBffSessionStore : ITicketStore
{
    /// <summary>
    /// Removes the sessions matching the specified criteria. Only sessions whose principal contains a
    /// matching client registration identifier and, when specified, a matching subject ("sub")
    /// and session identifier ("sid") are removed.
    /// </summary>
    /// <param name="registrationId">The client registration identifier.</param>
    /// <param name="subject">The subject, if specified.</param>
    /// <param name="sessionId">The session identifier, if specified.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of sessions that were removed.</returns>
    ValueTask<int> RemoveSessionsAsync(string registrationId, string? subject,
        string? sessionId, CancellationToken cancellationToken);
}
