/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server;

public static partial class OpenIddictServerEvents
{
    /// <summary>
    /// Represents an event called when a server-side session is terminated, either by the end session
    /// endpoint or by <see cref="OpenIddictServerService.TerminateSessionAsync(string, CancellationToken)"/>.
    /// </summary>
    public sealed class ProcessSessionTerminationContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessSessionTerminationContext"/> class.
        /// </summary>
        public ProcessSessionTerminationContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the identifier of the session entry that is terminated.
        /// </summary>
        public required string SessionId { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether all the valid sessions sharing the login identifier
        /// and the subject of the terminated session should also be terminated (<see langword="true"/> by default).
        /// </summary>
        public bool IncludeLoginSessions { get; set; } = true;

        /// <summary>
        /// Gets or sets a boolean indicating whether the resolved sessions and their tokens should be revoked.
        /// </summary>
        public bool RevokeSessions { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the authorizations attached to the resolved sessions should be revoked.
        /// </summary>
        public bool RevokeAuthorizations { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether back-channel logout requests should be sent.
        /// </summary>
        public bool SendBackchannelLogoutRequests { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the front-channel logout URIs should be resolved.
        /// </summary>
        public bool ResolveFrontchannelLogoutUris { get; set; }

        /// <summary>
        /// Gets the session entries resolved for this termination.
        /// </summary>
        public List<object> Sessions { get; } = [];

        /// <summary>
        /// Gets the client applications that participated in the resolved sessions.
        /// </summary>
        public List<OpenIddictServerLogoutParticipant> Participants { get; } = [];

        /// <summary>
        /// Gets the front-channel logout URIs that must be rendered by the user agent.
        /// </summary>
        public List<Uri> FrontchannelLogoutUris { get; } = [];

        /// <summary>
        /// Gets the participants for which a back-channel logout request was successfully sent.
        /// </summary>
        public List<OpenIddictServerLogoutParticipant> NotifiedParticipants { get; } = [];

        /// <summary>
        /// Gets the participants for which the back-channel logout request failed.
        /// </summary>
        public List<OpenIddictServerLogoutParticipant> FailedParticipants { get; } = [];
    }

    /// <summary>
    /// Represents an event called for each back-channel logout request that must be sent to a client application.
    /// The request is expected to be sent by a transport integration (e.g OpenIddict.Server.SystemNetHttp).
    /// </summary>
    public sealed class SendBackchannelLogoutRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="SendBackchannelLogoutRequestContext"/> class.
        /// </summary>
        public SendBackchannelLogoutRequestContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the participant the logout token is sent to.
        /// </summary>
        public required OpenIddictServerLogoutParticipant Participant { get; set; }

        /// <summary>
        /// Gets or sets the back-channel logout URI.
        /// </summary>
        public required Uri Uri { get; set; }

        /// <summary>
        /// Gets or sets the logout token.
        /// </summary>
        public required string LogoutToken { get; set; }

        /// <summary>
        /// Gets or sets the maximum amount of time allowed to send the request.
        /// </summary>
        public TimeSpan Timeout { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the request was sent and accepted by the client application.
        /// </summary>
        public bool IsSent { get; set; }
    }
}

/// <summary>
/// Represents a client application that participated in a terminated session.
/// </summary>
public sealed class OpenIddictServerLogoutParticipant
{
    /// <summary>
    /// Gets the identifier of the application entry.
    /// </summary>
    public required string ApplicationId { get; init; }

    /// <summary>
    /// Gets the client identifier of the application.
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// Gets the identifier of the session entry (used as the "sid" claim).
    /// </summary>
    public required string SessionId { get; init; }

    /// <summary>
    /// Gets the subject attached to the session, if available.
    /// </summary>
    public string? Subject { get; init; }

    /// <summary>
    /// Gets the back-channel logout URI registered by the application, if available.
    /// </summary>
    public Uri? BackchannelLogoutUri { get; init; }

    /// <summary>
    /// Gets a boolean indicating whether the application requires the "sid" claim in logout tokens.
    /// </summary>
    public bool BackchannelLogoutSessionRequired { get; init; }

    /// <summary>
    /// Gets the front-channel logout URI registered by the application, if available.
    /// </summary>
    public Uri? FrontchannelLogoutUri { get; init; }

    /// <summary>
    /// Gets a boolean indicating whether the application requires the "iss" and "sid" query parameters.
    /// </summary>
    public bool FrontchannelLogoutSessionRequired { get; init; }
}
