/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    /// <summary>
    /// Contains the handlers implementing server-side sessions lifecycle, OpenID Connect Back-Channel Logout 1.0,
    /// OpenID Connect Front-Channel Logout 1.0 and OpenID Connect Session Management 1.0.
    /// </summary>
    public static class Logout
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Top-level request processing:
             */
            InferCheckSessionIframeEndpointType.Descriptor,

            /*
             * Sign-in processing:
             */
            CreateSessionEntry.Descriptor,
            ExtendSessionEntry.Descriptor,
            AttachAccessTokenSessionId.Descriptor,

            /*
             * Sign-out processing:
             */
            TerminateSignOutSession.Descriptor,

            /*
             * Session termination processing:
             */
            ResolveSessionEntries.Descriptor,
            ResolveLogoutParticipants.Descriptor,
            RevokeSessionEntries.Descriptor,
            SendBackchannelLogoutRequests.Descriptor,
            AttachFrontchannelLogoutUris.Descriptor,

            /*
             * Token generation:
             */
            AttachLogoutTokenParameters.Descriptor,

            /*
             * Responses processing:
             */
            AttachEndSessionFrontchannelLogoutUris.Descriptor,
            AttachSessionState.Descriptor,

            /*
             * Discovery processing:
             */
            AttachLogoutMetadata.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for inferring the check session iframe endpoint type from the request URI.
        /// </summary>
        public sealed class InferCheckSessionIframeEndpointType : IOpenIddictServerHandler<ProcessRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .UseSingletonHandler<InferCheckSessionIframeEndpointType>()
                    .SetOrder(InferEndpointType.Descriptor.Order + 100)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context is not { EndpointType: OpenIddictServerEndpointType.Unknown,
                    BaseUri.IsAbsoluteUri: true, RequestUri.IsAbsoluteUri: true } ||
                    !context.Options.EnableSessionManagement)
                {
                    return ValueTask.CompletedTask;
                }

                foreach (var candidate in context.Options.CheckSessionIframeEndpointUris)
                {
                    var uri = candidate.IsAbsoluteUri ? candidate : OpenIddictHelpers.CreateAbsoluteUri(context.BaseUri, candidate);
                    if (OpenIddictHelpers.IsImplicitFileUri(uri) || (!candidate.IsAbsoluteUri && !OpenIddictHelpers.IsBaseOf(context.BaseUri, uri)))
                    {
                        continue;
                    }

                    if (string.Equals(uri.Scheme, context.RequestUri.Scheme, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(uri.Host, context.RequestUri.Host, StringComparison.OrdinalIgnoreCase) &&
                        uri.Port == context.RequestUri.Port &&
                        string.Equals(uri.AbsolutePath.TrimEnd('/'), context.RequestUri.AbsolutePath.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
                    {
                        context.EndpointType = OpenIddictServerEndpointType.CheckSessionIframe;
                        context.Logger.LogInformation(6053, SR.GetResourceString(SR.ID6053), context.EndpointType);

                        break;
                    }
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for adding the standard "sid" claim to access tokens, if enabled.
        /// </summary>
        public sealed class AttachAccessTokenSessionId : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireAccessTokenGenerated>()
                    .UseSingletonHandler<AttachAccessTokenSessionId>()
                    .SetOrder(PrepareAccessTokenPrincipal.Descriptor.Order + 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessSignInContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.Options.IncludeSessionIdInAccessTokens && context.AccessTokenPrincipal is ClaimsPrincipal principal &&
                    principal.GetSessionId() is { Length: > 0 } identifier)
                {
                    principal.SetClaim(Claims.SessionId, identifier);
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for creating (or reusing) a server-side session entry for sign-in demands
        /// processed by the authorization endpoint, when automatic session creation is enabled. The session is bound
        /// to the subject, the client application, the authorization and the login identifier specified by the host
        /// using the <see cref="Properties.LoginId"/> property, and its identifier is attached to the principal so that
        /// it flows to the derived tokens (and to the standard "sid" claim of identity tokens).
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class CreateSessionEntry : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseSingletonHandler<CreateSessionEntry>()
                    .SetOrder(AttachAuthorization.Descriptor.Order + 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessSignInContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!context.Options.EnableAutomaticSessionCreation ||
                    context.EndpointType is not OpenIddictServerEndpointType.Authorization ||
                    context.Principal is not { Identity: ClaimsIdentity } principal ||
                    !string.IsNullOrEmpty(principal.GetSessionId()) ||
                    principal.GetClaim(Claims.Subject) is not { Length: > 0 } subject)
                {
                    return;
                }

                var sessions = context.ServiceProvider.GetService<IOpenIddictSessionManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                string? application = null;

                if (!string.IsNullOrEmpty(context.Request.ClientId))
                {
                    var applications = context.ServiceProvider.GetService<IOpenIddictApplicationManager>()
                        ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                    var entry = await applications.FindByClientIdAsync(context.Request.ClientId, context.CancellationToken)
                        ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0017));

                    application = await applications.GetIdAsync(entry, context.CancellationToken);
                }

                var authorization = principal.GetAuthorizationId();
                var login = context.Properties.TryGetValue(Properties.LoginId, out string? value) && !string.IsNullOrEmpty(value) ? value : null;

                // When a login identifier is available (i.e when the host identifies the end-user authentication),
                // reuse the valid session already created for the same authentication, client and authorization.
                // Without a login identifier, sessions can't be safely correlated and a new entry is always created.
                if (!string.IsNullOrEmpty(login))
                {
                    await foreach (var candidate in sessions.FindAsync(
                        (subject, login, application, authorization, Statuses.Valid), context.CancellationToken))
                    {
                        if ((application is null && !string.IsNullOrEmpty(await sessions.GetApplicationIdAsync(candidate, context.CancellationToken))) ||
                            (authorization is null && !string.IsNullOrEmpty(await sessions.GetAuthorizationIdAsync(candidate, context.CancellationToken))) ||
                            await sessions.HasExpiredAsync(candidate, context.CancellationToken))
                        {
                            continue;
                        }

                        principal.SetSessionId(await sessions.GetIdAsync(candidate, context.CancellationToken));

                        return;
                    }
                }

                var date = context.Options.TimeProvider.GetUtcNow();

                var session = await sessions.CreateAsync(new OpenIddictSessionDescriptor
                {
                    ApplicationId = application,
                    AuthorizationId = authorization,
                    CreationDate = date,
                    ExpirationDate = OpenIddictServerHelpers.ComputeSessionExpirationDate(context.Options, date, date),
                    LastActivityDate = date,
                    LoginId = login,
                    Status = Statuses.Valid,
                    Subject = subject
                }, context.CancellationToken);

                var identifier = await sessions.GetIdAsync(session, context.CancellationToken);

                context.Logger.LogInformation(6535, SR.GetResourceString(SR.ID6535), identifier, context.Request.ClientId);

                principal.SetSessionId(identifier);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating and extending the lifetime of the session attached to a sign-in
        /// demand (sliding and absolute expiration), when a session idle timeout or lifetime is configured. Sign-in demands
        /// referencing a session that was revoked or that has expired are rejected, as the tokens derived from them would
        /// be unusable and extending an expired session would otherwise silently revive it.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ExtendSessionEntry : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseSingletonHandler<ExtendSessionEntry>()
                    .SetOrder(CreateSessionEntry.Descriptor.Order + 100)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessSignInContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.Options is { SessionIdleTimeout: null, SessionLifetime: null } ||
                    context.Principal?.GetSessionId() is not { Length: > 0 } identifier)
                {
                    return;
                }

                var manager = context.ServiceProvider.GetService<IOpenIddictSessionManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var session = await manager.FindByIdAsync(identifier, context.CancellationToken);
                if (session is null || !await manager.HasStatusAsync(session, Statuses.Valid, context.CancellationToken) ||
                    await manager.HasExpiredAsync(session, context.CancellationToken))
                {
                    context.Logger.LogInformation(6536, SR.GetResourceString(SR.ID6536), identifier);

                    context.Reject(
                        error: context.EndpointType is OpenIddictServerEndpointType.Authorization ? Errors.LoginRequired : Errors.InvalidGrant,
                        description: SR.GetResourceString(SR.ID2363),
                        uri: SR.FormatID8000(SR.ID2363));

                    return;
                }

                var date = context.Options.TimeProvider.GetUtcNow();
                var expiration = OpenIddictServerHelpers.ComputeSessionExpirationDate(context.Options, date,
                    await manager.GetCreationDateAsync(session, context.CancellationToken));

                // To limit the number of writes, don't update the session if the expiration date
                // didn't significantly change (e.g when multiple tokens are issued in a short period).
                var current = await manager.GetExpirationDateAsync(session, context.CancellationToken);
                var activity = await manager.GetLastActivityDateAsync(session, context.CancellationToken);
                if (activity is not null && date - activity.Value < TimeSpan.FromMinutes(1) &&
                    (expiration is null || current is not null && (expiration.Value - current.Value).Duration() < TimeSpan.FromMinutes(1)))
                {
                    return;
                }

                await manager.TryExtendAsync(session, date, expiration, context.CancellationToken);
            }
        }

        /// <summary>
        /// Contains the logic responsible for terminating the session attached to a sign-out demand processed by
        /// the end session endpoint, when session revocation, back-channel logout or front-channel logout are enabled.
        /// The session is resolved from the <see cref="Properties.SessionId"/> host property or, only when
        /// <see cref="OpenIddictServerOptions.EnableIdentityTokenHintSessionResolution"/> is enabled, from the "sid" claim
        /// of the identity token hint. Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class TerminateSignOutSession : IOpenIddictServerHandler<ProcessSignOutContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public TerminateSignOutSession(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                    .AddFilter<RequireEndSessionRequest>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseSingletonHandler<TerminateSignOutSession>()
                    .SetOrder(RedeemLogoutTokenEntry.Descriptor.Order + 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessSignOutContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.Options is { EnableSessionRevocationOnSignOut: false, EnableBackchannelLogout: false,
                                         EnableFrontchannelLogout: false })
                {
                    return;
                }

                var identifier = context.Properties.TryGetValue(Properties.SessionId, out string? value) && !string.IsNullOrEmpty(value)
                    ? value : null;

                // Note: an identity token hint only proves that the RP was issued a token for the session, not that the
                // session belongs to the user currently authenticated at the OP (RP-Initiated Logout 1.0, section 2 requires
                // treating mismatched requests as suspect). As such, the "sid" claim of the hint is only used as a fallback
                // when explicitly allowed. Hints whose session expired are still accepted (the lifetime of hints is not
                // validated), which allows notifying the RPs that had a recent session at the OP.
                if (string.IsNullOrEmpty(identifier) && context.Options.EnableIdentityTokenHintSessionResolution)
                {
                    identifier = context.Transaction.GetProperty<ProcessAuthenticationContext>(typeof(ProcessAuthenticationContext).FullName!)
                        ?.IdentityTokenPrincipal?.GetClaim(Claims.SessionId);
                }

                if (string.IsNullOrEmpty(identifier))
                {
                    context.Logger.LogDebug(6525, SR.GetResourceString(SR.ID6525));

                    return;
                }

                var notification = new ProcessSessionTerminationContext(context.Transaction)
                {
                    SessionId = identifier,
                    RevokeSessions = context.Options.EnableSessionRevocationOnSignOut,
                    RevokeAuthorizations = context.Options.EnableSessionRevocationOnSignOut &&
                                           context.Options.RevokeAuthorizationsOnSessionTermination,
                    SendBackchannelLogoutRequests = context.Options.EnableBackchannelLogout,
                    ResolveFrontchannelLogoutUris = context.Options.EnableFrontchannelLogout
                };

                await _dispatcher.DispatchAsync(notification);

                // Note: a failed session termination doesn't prevent the user agent from being logged out.
                if (notification.IsRejected)
                {
                    context.Logger.LogWarning(6532, SR.GetResourceString(SR.ID6532), notification.Error, notification.ErrorDescription);

                    return;
                }

                // Store the context object in the transaction so it can be later retrieved by the
                // handlers responsible for attaching the front-channel logout URIs to the response.
                context.Transaction.SetProperty(typeof(ProcessSessionTerminationContext).FullName!, notification);
            }
        }

        /// <summary>
        /// Contains the logic responsible for resolving the session entries affected by a session termination.
        /// </summary>
        public sealed class ResolveSessionEntries : IOpenIddictServerHandler<ProcessSessionTerminationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSessionTerminationContext>()
                    .UseSingletonHandler<ResolveSessionEntries>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessSessionTerminationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var manager = context.ServiceProvider.GetService<IOpenIddictSessionManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var session = await manager.FindByIdAsync(context.SessionId, context.CancellationToken);
                if (session is null)
                {
                    context.Logger.LogInformation(6526, SR.GetResourceString(SR.ID6526), context.SessionId);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2362(context.SessionId),
                        uri: SR.FormatID8000(SR.ID2362));

                    return;
                }

                // Don't notify the client applications again when the session was already terminated.
                if (!await manager.HasStatusAsync(session, Statuses.Valid, context.CancellationToken))
                {
                    context.Logger.LogInformation(6537, SR.GetResourceString(SR.ID6537), context.SessionId);

                    return;
                }

                context.Sessions.Add(session);

                // A single authentication of the end user (represented by a login identifier) is typically associated
                // with a session entry per client application: to ensure all the client applications that participated
                // in the same OP session are logged out, the valid sessions sharing the login identifier are also resolved.
                var login = await manager.GetLoginIdAsync(session, context.CancellationToken);
                if (!context.IncludeLoginSessions || string.IsNullOrEmpty(login))
                {
                    return;
                }

                var subject = await manager.GetSubjectAsync(session, context.CancellationToken);

                await foreach (var candidate in manager.FindByLoginIdAsync(login, context.CancellationToken))
                {
                    if (string.Equals(await manager.GetIdAsync(candidate, context.CancellationToken), context.SessionId, StringComparison.Ordinal) ||
                        !string.Equals(await manager.GetSubjectAsync(candidate, context.CancellationToken), subject, StringComparison.Ordinal) ||
                        !await manager.HasStatusAsync(candidate, Statuses.Valid, context.CancellationToken))
                    {
                        continue;
                    }

                    context.Sessions.Add(candidate);
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for resolving the client applications that participated in the terminated sessions.
        /// </summary>
        public sealed class ResolveLogoutParticipants : IOpenIddictServerHandler<ProcessSessionTerminationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSessionTerminationContext>()
                    .UseSingletonHandler<ResolveLogoutParticipants>()
                    .SetOrder(ResolveSessionEntries.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessSessionTerminationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!context.SendBackchannelLogoutRequests && !context.ResolveFrontchannelLogoutUris)
                {
                    return;
                }

                var sessions = context.ServiceProvider.GetService<IOpenIddictSessionManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var applications = context.ServiceProvider.GetService<IOpenIddictApplicationManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                foreach (var session in context.Sessions)
                {
                    var identifier = await sessions.GetApplicationIdAsync(session, context.CancellationToken);
                    if (string.IsNullOrEmpty(identifier))
                    {
                        continue;
                    }

                    var application = await applications.FindByIdAsync(identifier, context.CancellationToken);
                    if (application is null)
                    {
                        continue;
                    }

                    var client = await applications.GetClientIdAsync(application, context.CancellationToken);
                    if (string.IsNullOrEmpty(client))
                    {
                        continue;
                    }

                    var settings = await applications.GetSettingsAsync(application, context.CancellationToken)
                        ?? ImmutableDictionary<string, string>.Empty;

                    context.Participants.Add(new OpenIddictServerLogoutParticipant
                    {
                        ApplicationId = identifier,
                        ClientId = client,
                        SessionId = (await sessions.GetIdAsync(session, context.CancellationToken))!,
                        Subject = await sessions.GetSubjectAsync(session, context.CancellationToken),
                        BackchannelLogoutUri = GetUri(settings, Settings.Logout.BackchannelLogoutUri, client),
                        BackchannelLogoutSessionRequired = GetBoolean(settings, Settings.Logout.BackchannelLogoutSessionRequired),
                        FrontchannelLogoutUri = GetUri(settings, Settings.Logout.FrontchannelLogoutUri, client),
                        FrontchannelLogoutSessionRequired = GetBoolean(settings, Settings.Logout.FrontchannelLogoutSessionRequired)
                    });
                }

                Uri? GetUri(ImmutableDictionary<string, string> settings, string name, string client)
                {
                    if (!settings.TryGetValue(name, out string? value) || string.IsNullOrEmpty(value))
                    {
                        return null;
                    }

                    if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) || uri.Scheme is not ("http" or "https") ||
                        !string.IsNullOrEmpty(uri.Fragment))
                    {
                        context.Logger.LogWarning(6533, SR.GetResourceString(SR.ID6533), value, client);

                        return null;
                    }

                    return uri;
                }

                static bool GetBoolean(ImmutableDictionary<string, string> settings, string name)
                    => settings.TryGetValue(name, out string? value) && bool.TryParse(value, out bool result) && result;
            }
        }

        /// <summary>
        /// Contains the logic responsible for revoking the terminated sessions, their tokens and, if configured, their authorizations.
        /// </summary>
        public sealed class RevokeSessionEntries : IOpenIddictServerHandler<ProcessSessionTerminationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSessionTerminationContext>()
                    .UseSingletonHandler<RevokeSessionEntries>()
                    .SetOrder(ResolveLogoutParticipants.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessSessionTerminationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!context.RevokeSessions)
                {
                    return;
                }

                var sessions = context.ServiceProvider.GetService<IOpenIddictSessionManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var tokens = context.ServiceProvider.GetService<IOpenIddictTokenManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                foreach (var session in context.Sessions)
                {
                    var identifier = (await sessions.GetIdAsync(session, context.CancellationToken))!;

                    await sessions.TryRevokeAsync(session, context.CancellationToken);
                    await tokens.RevokeBySessionIdAsync(identifier, context.CancellationToken);

                    if (!context.RevokeAuthorizations)
                    {
                        continue;
                    }

                    var authorization = await sessions.GetAuthorizationIdAsync(session, context.CancellationToken);
                    if (string.IsNullOrEmpty(authorization))
                    {
                        continue;
                    }

                    var authorizations = context.ServiceProvider.GetService<IOpenIddictAuthorizationManager>()
                        ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                    if (await authorizations.FindByIdAsync(authorization, context.CancellationToken) is object entry)
                    {
                        await authorizations.TryRevokeAsync(entry, context.CancellationToken);
                        await tokens.RevokeByAuthorizationIdAsync(authorization, context.CancellationToken);
                    }
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for generating logout tokens and sending them to the back-channel logout URIs
        /// of the participants, as defined by OpenID Connect Back-Channel Logout 1.0.
        /// </summary>
        public sealed class SendBackchannelLogoutRequests : IOpenIddictServerHandler<ProcessSessionTerminationContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public SendBackchannelLogoutRequests(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSessionTerminationContext>()
                    .UseSingletonHandler<SendBackchannelLogoutRequests>()
                    .SetOrder(RevokeSessionEntries.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessSessionTerminationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!context.SendBackchannelLogoutRequests)
                {
                    return;
                }

                string? issuer = null;

                // Note: logout tokens are generated sequentially (as token generation may rely on scoped
                // services like the key store) but the requests are sent in parallel to reduce latency.
                List<(OpenIddictServerLogoutParticipant Participant, string Token)> requests = [];

                foreach (var participant in context.Participants)
                {
                    if (participant.BackchannelLogoutUri is null)
                    {
                        continue;
                    }

                    var date = context.Options.TimeProvider.GetUtcNow();

                    // See https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken for more information.
                    var principal = new ClaimsPrincipal(new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType))
                        .SetCreationDate(date)
                        .SetExpirationDate(date + context.Options.LogoutTokenLifetime)
                        .SetClaim(Claims.Private.Issuer, issuer ??= GetIssuer(context))
                        .SetClaim(Claims.Audience, participant.ClientId)
                        .SetClaim(Claims.JwtId, Guid.NewGuid().ToString())
                        .SetClaim(Claims.Subject, participant.Subject)
                        .SetClaim(Claims.SessionId, participant.SessionId);

                    // Note: the "events" claim MUST be a JSON object containing the back-channel logout event.
                    // A "nonce" claim is never added, as it is prohibited in logout tokens.
                    ((ClaimsIdentity) principal.Identity!).AddClaim(new Claim(Claims.Events,
                        "{\"" + SecurityEventTypes.BackchannelLogout + "\":{}}", JsonClaimValueTypes.Json));

                    var notification = new GenerateTokenContext(context.Transaction)
                    {
                        ClientId = participant.ClientId,
                        CreateTokenEntry = false,
                        IsReferenceToken = false,
                        PersistTokenPayload = false,
                        Principal = principal,
                        TokenFormat = TokenFormats.Private.JsonWebToken,
                        TokenType = TokenTypeIdentifiers.Private.LogoutToken
                    };

                    try
                    {
                        await _dispatcher.DispatchAsync(notification);
                    }

                    catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                    {
                        context.Logger.LogWarning(6531, exception, SR.GetResourceString(SR.ID6531),
                            participant.ClientId, exception.GetType().Name, exception.Message);
                        context.FailedParticipants.Add(participant);

                        continue;
                    }

                    if (notification.IsRejected || string.IsNullOrEmpty(notification.Token))
                    {
                        context.Logger.LogWarning(6531, SR.GetResourceString(SR.ID6531),
                            participant.ClientId, notification.Error, notification.ErrorDescription);
                        context.FailedParticipants.Add(participant);

                        continue;
                    }

                    requests.Add((participant, notification.Token));
                }

                var results = await Task.WhenAll(requests.Select(request => SendAsync(request.Participant, request.Token)));

                for (var index = 0; index < requests.Count; index++)
                {
                    (results[index] ? context.NotifiedParticipants : context.FailedParticipants).Add(requests[index].Participant);
                }

                async Task<bool> SendAsync(OpenIddictServerLogoutParticipant participant, string token)
                {
                    using var source = CancellationTokenSource.CreateLinkedTokenSource(context.CancellationToken);
                    source.CancelAfter(context.Options.BackchannelLogoutTimeout);

                    // Note: the requests are sent concurrently: to avoid sharing non-thread-safe scoped services
                    // (e.g a DbContext) between the transport handlers, a child scope is created for each request.
                    using var scope = context.ServiceProvider.GetService<IServiceScopeFactory>()?.CreateScope();

                    var transaction = new OpenIddictServerTransaction
                    {
                        BaseUri = context.BaseUri,
                        CancellationToken = source.Token,
                        Options = context.Options,
                        RequestUri = context.RequestUri,
                        ServiceProvider = scope?.ServiceProvider ?? context.ServiceProvider
                    };

                    var notification = new SendBackchannelLogoutRequestContext(transaction)
                    {
                        LogoutToken = token,
                        Participant = participant,
                        Timeout = context.Options.BackchannelLogoutTimeout,
                        Uri = participant.BackchannelLogoutUri!
                    };

                    try
                    {
                        await _dispatcher.DispatchAsync(notification);
                    }

                    catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                    {
                        context.Logger.LogWarning(6530, exception, SR.GetResourceString(SR.ID6530), notification.Uri, participant.ClientId);

                        return false;
                    }

                    if (notification.IsRejected)
                    {
                        context.Logger.LogWarning(6527, SR.GetResourceString(SR.ID6527), notification.Uri,
                            participant.ClientId, notification.Error, notification.ErrorDescription);

                        return false;
                    }

                    if (!notification.IsSent)
                    {
                        context.Logger.LogWarning(6529, SR.GetResourceString(SR.ID6529), notification.Uri);

                        return false;
                    }

                    context.Logger.LogInformation(6528, SR.GetResourceString(SR.ID6528), notification.Uri, participant.ClientId);

                    return true;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for computing the front-channel logout URIs of the participants,
        /// as defined by OpenID Connect Front-Channel Logout 1.0.
        /// </summary>
        public sealed class AttachFrontchannelLogoutUris : IOpenIddictServerHandler<ProcessSessionTerminationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSessionTerminationContext>()
                    .UseSingletonHandler<AttachFrontchannelLogoutUris>()
                    .SetOrder(SendBackchannelLogoutRequests.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessSessionTerminationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!context.ResolveFrontchannelLogoutUris)
                {
                    return ValueTask.CompletedTask;
                }

                string? issuer = null;

                foreach (var participant in context.Participants)
                {
                    if (participant.FrontchannelLogoutUri is null)
                    {
                        continue;
                    }

                    // Note: since the server advertises "frontchannel_logout_session_supported", the "iss" and "sid"
                    // query parameters are always added (they are REQUIRED when frontchannel_logout_session_required
                    // is true). See https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout.
                    var uri = OpenIddictHelpers.AddQueryStringParameters(participant.FrontchannelLogoutUri,
                        new Dictionary<string, StringValues>(StringComparer.Ordinal)
                        {
                            [Parameters.Iss] = issuer ??= GetIssuer(context),
                            [Parameters.Sid] = participant.SessionId
                        });

                    if (!context.FrontchannelLogoutUris.Contains(uri))
                    {
                        context.FrontchannelLogoutUris.Add(uri);
                    }
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for adjusting the security parameters of logout tokens:
        /// logout tokens are never encrypted, are signed using an asymmetric key and use the "logout+jwt" type.
        /// </summary>
        public sealed class AttachLogoutTokenParameters : IOpenIddictServerHandler<GenerateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .UseSingletonHandler<AttachLogoutTokenParameters>()
                    .SetOrder(Protection.AttachTokenMetadata.Descriptor.Order + 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(GenerateTokenContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.TokenType is not TokenTypeIdentifiers.Private.LogoutToken)
                {
                    return;
                }

                var credentials = await OpenIddictServerKeyRing.ResolveCredentialsAsync(context.Transaction);

                // Note: logout tokens are validated by client applications using the public keys exposed by the server.
                context.EncryptionCredentials = null;
                context.SigningCredentials = credentials.SigningCredentials.FirstOrDefault(
                    static credentials => credentials.Key is AsymmetricSecurityKey)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0720));

                // See https://openid.net/specs/openid-connect-backchannel-1_0.html#Security for more information.
                context.SecurityTokenDescriptor.TokenType = JsonWebTokenTypes.LogoutToken;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the front-channel logout URIs resolved during the sign-out.
        /// </summary>
        public sealed class AttachEndSessionFrontchannelLogoutUris : IOpenIddictServerHandler<ApplyEndSessionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyEndSessionResponseContext>()
                    .UseSingletonHandler<AttachEndSessionFrontchannelLogoutUris>()
                    .SetOrder(Session.AttachResponseState.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyEndSessionResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!string.IsNullOrEmpty(context.Response.Error) || !string.IsNullOrEmpty(context.Response.RequestUri))
                {
                    return ValueTask.CompletedTask;
                }

                var notification = context.Transaction.GetProperty<ProcessSessionTerminationContext>(
                    typeof(ProcessSessionTerminationContext).FullName!);

                if (notification is { FrontchannelLogoutUris.Count: > 0 })
                {
                    foreach (var uri in notification.FrontchannelLogoutUris)
                    {
                        if (!context.FrontchannelLogoutUris.Contains(uri))
                        {
                            context.FrontchannelLogoutUris.Add(uri);
                        }
                    }
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the "session_state" parameter to successful authorization
        /// responses, as defined by OpenID Connect Session Management 1.0. The OP browser state is expected to be
        /// attached to the transaction by the host (see <see cref="OpenIddictServerTransaction.BrowserState"/>).
        /// </summary>
        public sealed class AttachSessionState : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                    .UseSingletonHandler<AttachSessionState>()
                    // Note: this handler must be executed after the redirect_uri is resolved but before the
                    // response is applied by the host (which typically happens with an order of 250 000).
                    .SetOrder(100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!context.Options.EnableSessionManagement || string.IsNullOrEmpty(context.Transaction.BrowserState) ||
                    !string.IsNullOrEmpty(context.Response.Error) || !string.IsNullOrEmpty(context.Response.RequestUri) ||
                    !string.IsNullOrEmpty((string?) context.Response[Parameters.SessionState]) ||
                    context.Request is not { ClientId.Length: > 0 } request || !request.HasScope(Scopes.OpenId) ||
                    !Uri.TryCreate(context.RedirectUri, UriKind.Absolute, out Uri? uri))
                {
                    return ValueTask.CompletedTask;
                }

                // See https://openid.net/specs/openid-connect-session-1_0.html#CreatingUpdatingSessions.
                context.Response[Parameters.SessionState] = OpenIddictServerHelpers.ComputeSessionState(
                    request.ClientId, uri.GetLeftPart(UriPartial.Authority), context.Transaction.BrowserState);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the logout and session management metadata to the discovery document.
        /// </summary>
        public sealed class AttachLogoutMetadata : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachLogoutMetadata>()
                    .SetOrder(Discovery.AttachAdditionalMetadata.Descriptor.Order + 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // See https://openid.net/specs/openid-connect-backchannel-1_0.html#BCSupport.
                if (context.Options.EnableBackchannelLogout)
                {
                    context.Metadata[Metadata.BackchannelLogoutSupported] = true;
                    context.Metadata[Metadata.BackchannelLogoutSessionSupported] = true;
                }

                // See https://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout.
                if (context.Options.EnableFrontchannelLogout)
                {
                    context.Metadata[Metadata.FrontchannelLogoutSupported] = true;
                    context.Metadata[Metadata.FrontchannelLogoutSessionSupported] = true;
                }

                // See https://openid.net/specs/openid-connect-session-1_0.html#OPMetadata.
                if (context.Options.EnableSessionManagement && context.BaseUri is not null &&
                    context.Options.CheckSessionIframeEndpointUris.FirstOrDefault() is Uri endpoint)
                {
                    context.Metadata[Metadata.CheckSessionIframe] =
                        OpenIddictHelpers.CreateAbsoluteUri(context.BaseUri, endpoint).AbsoluteUri;
                }

                return ValueTask.CompletedTask;
            }
        }

        private static string GetIssuer(BaseContext context) => (context.Options.Issuer ?? context.BaseUri) switch
        {
            { IsAbsoluteUri: true } uri => uri.AbsoluteUri,

            // When no request is being processed (e.g when a session is terminated using OpenIddictServerService),
            // the issuer can't be inferred from the base URI and must be explicitly configured.
            null => throw new InvalidOperationException(SR.GetResourceString(SR.ID0726)),

            // Throw an exception if the issuer cannot be retrieved or is not valid.
            _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0496))
        };
    }
}
