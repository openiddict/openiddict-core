/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client;

/// <summary>
/// Represents a store able to terminate the local sessions targeted by the logout requests sent by
/// authorization servers to the back-channel and front-channel logout endpoints of the client.
/// </summary>
/// <remarks>
/// <para>
/// Implementations are invoked after the logout requests have been fully validated, unless
/// the pass-through mode was enabled for the corresponding endpoint in the host integration.
/// For front-channel logout requests, implementations are only invoked when the request was verified as being
/// bound to the session attached to the user agent (see <see cref="OpenIddictClientOptions.DisableFrontchannelLogoutSessionVerification"/>).
/// </para>
/// <para>
/// As required by <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#BCActions">OpenID Connect
/// Back-Channel Logout 1.0, section 2.7</see>, implementations are also expected to revoke the refresh tokens
/// attached to the removed sessions that were not issued with the "offline_access" scope.
/// If an exception is thrown, the logout request is considered failed and the logout token can be sent again.
/// </para>
/// </remarks>
public interface IOpenIddictClientSessionStore
{
    /// <summary>
    /// Removes the sessions matching the specified criteria. As required by
    /// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#BCActions">OpenID Connect
    /// Back-Channel Logout 1.0, section 2.7</see>, when a session identifier is specified, only the session
    /// identified by <paramref name="sessionId"/> must be removed. Otherwise, all the sessions of the subject
    /// identified by <paramref name="subject"/> and created using the specified registration must be removed.
    /// </summary>
    /// <param name="registration">The client registration associated with the authorization server.</param>
    /// <param name="subject">The subject ("sub") specified by the authorization server, if available.</param>
    /// <param name="sessionId">The session identifier ("sid") specified by the authorization server, if available.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of sessions that were removed.</returns>
    ValueTask<long> RemoveSessionsAsync(OpenIddictClientRegistration registration,
        string? subject, string? sessionId, CancellationToken cancellationToken);
}
