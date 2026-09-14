/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client;

public static partial class OpenIddictClientHandlers
{
    /// <summary>
    /// Contains the handlers implementing the relying party side of OpenID Connect Back-Channel Logout 1.0,
    /// OpenID Connect Front-Channel Logout 1.0 and OpenID Connect Session Management 1.0.
    /// </summary>
    public static class Logout
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Back-channel logout request top-level processing:
             */
            ExtractBackchannelLogoutRequest.Descriptor,
            ValidateBackchannelLogoutRequest.Descriptor,
            HandleBackchannelLogoutRequest.Descriptor,
            ApplyBackchannelLogoutResponse<ProcessErrorContext>.Descriptor,
            ApplyBackchannelLogoutResponse<ProcessRequestContext>.Descriptor,

            /*
             * Back-channel logout request validation and handling:
             */
            ValidateLogoutTokenAuthentication.Descriptor,
            RemoveBackchannelLogoutSessions.Descriptor,

            /*
             * Front-channel logout request top-level processing:
             */
            ExtractFrontchannelLogoutRequest.Descriptor,
            ValidateFrontchannelLogoutRequest.Descriptor,
            HandleFrontchannelLogoutRequest.Descriptor,
            ApplyFrontchannelLogoutResponse<ProcessErrorContext>.Descriptor,
            ApplyFrontchannelLogoutResponse<ProcessRequestContext>.Descriptor,

            /*
             * Front-channel logout request validation and handling:
             */
            ValidateFrontchannelLogoutAuthentication.Descriptor,
            RemoveFrontchannelLogoutSessions.Descriptor,

            /*
             * Authentication processing:
             */
            EvaluateValidatedLogoutTokens.Descriptor,
            ResolveValidatedLogoutToken.Descriptor,
            ValidateRequiredLogoutToken.Descriptor,
            ResolveClientRegistrationFromLogoutToken.Descriptor,
            ResolveClientRegistrationFromFrontchannelLogoutRequest.Descriptor,
            ValidateLogoutToken.Descriptor,
            ValidateLogoutTokenWellknownClaims.Descriptor,
            ValidateLogoutTokenAudience.Descriptor,
            ValidateLogoutTokenLifetime.Descriptor,
            RedeemLogoutTokenIdentifier.Descriptor,
            ResolveSessionState.Descriptor,

            /*
             * Configuration response handling:
             */
            ExtractLogoutMetadata.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for extracting back-channel logout requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractBackchannelLogoutRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ExtractBackchannelLogoutRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireBackchannelLogoutRequest>()
                    .UseSingletonHandler<ExtractBackchannelLogoutRequest>()
                    .SetOrder(100_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ExtractBackchannelLogoutRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                if (notification.Request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0761));
                }

                context.Logger.LogInformation(6560, SR.GetResourceString(SR.ID6560), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating back-channel logout requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateBackchannelLogoutRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ValidateBackchannelLogoutRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireBackchannelLogoutRequest>()
                    .UseSingletonHandler<ValidateBackchannelLogoutRequest>()
                    .SetOrder(ExtractBackchannelLogoutRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ValidateBackchannelLogoutRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                context.Logger.LogInformation(6561, SR.GetResourceString(SR.ID6561));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling back-channel logout requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleBackchannelLogoutRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public HandleBackchannelLogoutRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireBackchannelLogoutRequest>()
                    .UseSingletonHandler<HandleBackchannelLogoutRequest>()
                    .SetOrder(ValidateBackchannelLogoutRequest.Descriptor.Order + 1_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var authentication = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                    typeof(ProcessAuthenticationContext).FullName!);

                var notification = new HandleBackchannelLogoutRequestContext(context.Transaction)
                {
                    Principal = authentication?.LogoutTokenPrincipal,
                    SessionId = authentication?.SessionId,
                    Subject = authentication?.Subject
                };

                try
                {
                    await _dispatcher.DispatchAsync(notification);
                }

                // If the sessions couldn't be terminated (e.g due to a transient session store failure), release
                // the logout token identifier so that the authorization server can retry delivering the same token.
                catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    await ReleaseLogoutTokenIdentifierAsync(context.Transaction, context.CancellationToken);
                    throw;
                }

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    await ReleaseLogoutTokenIdentifierAsync(context.Transaction, context.CancellationToken);

                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                context.Transaction.Response = new OpenIddictResponse();
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing back-channel logout responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyBackchannelLogoutResponse<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ApplyBackchannelLogoutResponse(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireBackchannelLogoutRequest>()
                    .UseSingletonHandler<ApplyBackchannelLogoutResponse<TContext>>()
                    .SetOrder(500_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ApplyBackchannelLogoutResponseContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0762));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting back-channel logout requests that don't specify a valid logout token.
        /// </summary>
        public sealed class ValidateLogoutTokenAuthentication : IOpenIddictClientHandler<ValidateBackchannelLogoutRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ValidateLogoutTokenAuthentication(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateBackchannelLogoutRequestContext>()
                    .UseSingletonHandler<ValidateLogoutTokenAuthentication>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateBackchannelLogoutRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ProcessAuthenticationContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by handlers
                // that want to access the authentication result without triggering a new authentication flow.
                context.Transaction.SetProperty(typeof(ProcessAuthenticationContext).FullName!, notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                context.Principal = notification.LogoutTokenPrincipal;
                context.SessionId = notification.SessionId;
                context.Subject = notification.Subject;
            }
        }

        /// <summary>
        /// Contains the logic responsible for removing the sessions matching a validated
        /// back-channel logout request using the registered session stores.
        /// Note: this handler is not used when the pass-through mode is enabled by the host.
        /// </summary>
        public sealed class RemoveBackchannelLogoutSessions : IOpenIddictClientHandler<HandleBackchannelLogoutRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleBackchannelLogoutRequestContext>()
                    .UseSingletonHandler<RemoveBackchannelLogoutSessions>()
                    // Note: this handler is deliberately executed after the handlers
                    // enabling the pass-through mode registered by the host integrations.
                    .SetOrder(int.MaxValue - 50_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(HandleBackchannelLogoutRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // As required by the specification, the relying party MUST respond with an error if the logout
                // failed. Since no session can be terminated without a session store, an exception is thrown
                // to inform the developer that the back-channel logout endpoint is not correctly configured.
                //
                // See https://openid.net/specs/openid-connect-backchannel-1_0.html#BCResponse for more information.
                var stores = context.ServiceProvider.GetServices<IOpenIddictClientSessionStore>().ToList();
                if (stores.Count is 0)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0760));
                }

                await RemoveSessionsAsync(context, stores, context.Subject, context.SessionId);
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting front-channel logout requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractFrontchannelLogoutRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ExtractFrontchannelLogoutRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireFrontchannelLogoutRequest>()
                    .UseSingletonHandler<ExtractFrontchannelLogoutRequest>()
                    .SetOrder(100_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ExtractFrontchannelLogoutRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                if (notification.Request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0763));
                }

                context.Logger.LogInformation(6562, SR.GetResourceString(SR.ID6562), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating front-channel logout requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateFrontchannelLogoutRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ValidateFrontchannelLogoutRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireFrontchannelLogoutRequest>()
                    .UseSingletonHandler<ValidateFrontchannelLogoutRequest>()
                    .SetOrder(ExtractFrontchannelLogoutRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ValidateFrontchannelLogoutRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                context.Logger.LogInformation(6563, SR.GetResourceString(SR.ID6563));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling front-channel logout requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleFrontchannelLogoutRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public HandleFrontchannelLogoutRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireFrontchannelLogoutRequest>()
                    .UseSingletonHandler<HandleFrontchannelLogoutRequest>()
                    .SetOrder(ValidateFrontchannelLogoutRequest.Descriptor.Order + 1_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var authentication = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                    typeof(ProcessAuthenticationContext).FullName!);

                var notification = new HandleFrontchannelLogoutRequestContext(context.Transaction)
                {
                    SessionId = authentication?.SessionId
                };

                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                context.Transaction.Response = new OpenIddictResponse();
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing front-channel logout responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyFrontchannelLogoutResponse<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ApplyFrontchannelLogoutResponse(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireFrontchannelLogoutRequest>()
                    .UseSingletonHandler<ApplyFrontchannelLogoutResponse<TContext>>()
                    .SetOrder(500_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ApplyFrontchannelLogoutResponseContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0764));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting front-channel logout requests that don't specify valid parameters.
        /// </summary>
        public sealed class ValidateFrontchannelLogoutAuthentication : IOpenIddictClientHandler<ValidateFrontchannelLogoutRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ValidateFrontchannelLogoutAuthentication(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateFrontchannelLogoutRequestContext>()
                    .UseSingletonHandler<ValidateFrontchannelLogoutAuthentication>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateFrontchannelLogoutRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ProcessAuthenticationContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by handlers
                // that want to access the authentication result without triggering a new authentication flow.
                context.Transaction.SetProperty(typeof(ProcessAuthenticationContext).FullName!, notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                context.SessionId = notification.SessionId;
            }
        }

        /// <summary>
        /// Contains the logic responsible for removing the session identified by a validated front-channel
        /// logout request using the registered session stores, if any. Unlike back-channel logout requests,
        /// front-channel logout requests are sent by the user agent, which allows the host integrations
        /// to also terminate the session attached to the current request (e.g an authentication cookie).
        /// Note: this handler is not used when the pass-through mode is enabled by the host.
        /// </summary>
        public sealed class RemoveFrontchannelLogoutSessions : IOpenIddictClientHandler<HandleFrontchannelLogoutRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleFrontchannelLogoutRequestContext>()
                    .UseSingletonHandler<RemoveFrontchannelLogoutSessions>()
                    // Note: this handler is deliberately executed after the handlers
                    // enabling the pass-through mode registered by the host integrations.
                    .SetOrder(int.MaxValue - 50_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(HandleFrontchannelLogoutRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (string.IsNullOrEmpty(context.SessionId))
                {
                    return;
                }

                var stores = context.ServiceProvider.GetServices<IOpenIddictClientSessionStore>().ToList();
                if (stores.Count is 0)
                {
                    return;
                }

                // Front-channel logout requests are not authenticated: the "iss" and "sid" parameters can be
                // forged by anyone knowing them (e.g another client of the same authorization server receiving
                // the same "sid" claim in its identity tokens). To prevent unrelated sessions from being terminated,
                // the session stores are only invoked if the request was verified as being bound to the session
                // attached to the user agent, unless session verification was explicitly disabled.
                //
                // See https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout for more information.
                if (!context.IsSessionVerified && !context.Options.DisableFrontchannelLogoutSessionVerification)
                {
                    context.Logger.LogInformation(6568, SR.GetResourceString(SR.ID6568), context.SessionId);
                    return;
                }

                await RemoveSessionsAsync(context, stores, subject: null, context.SessionId);
            }
        }

        /// <summary>
        /// Contains the logic responsible for determining whether a logout token must be validated.
        /// </summary>
        public sealed class EvaluateValidatedLogoutTokens : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<EvaluateValidatedLogoutTokens>()
                    .SetOrder(ResolveClientRegistrationFromAuthenticationContext.Descriptor.Order + 100)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                (context.ExtractLogoutToken,
                 context.RequireLogoutToken,
                 context.ValidateLogoutToken,
                 context.RejectLogoutToken) = context.EndpointType switch
                {
                    // Back-channel logout requests MUST include a logout token.
                    //
                    // See https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRequest for more information.
                    OpenIddictClientEndpointType.BackchannelLogout => (true, true, true, true),

                    _ => (false, false, false, false)
                };

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for resolving the logout token from the incoming request.
        /// </summary>
        public sealed class ResolveValidatedLogoutToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ResolveValidatedLogoutToken>()
                    .SetOrder(EvaluateValidatedLogoutTokens.Descriptor.Order + 100)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                context.LogoutToken ??= context.EndpointType switch
                {
                    OpenIddictClientEndpointType.BackchannelLogout when context.ExtractLogoutToken
                        => (string?) context.Request?[Parameters.LogoutToken],

                    _ => null
                };

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authentication demands that lack the required logout token.
        /// </summary>
        public sealed class ValidateRequiredLogoutToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateRequiredLogoutToken>()
                    .SetOrder(ResolveValidatedLogoutToken.Descriptor.Order + 100)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.RequireLogoutToken && string.IsNullOrEmpty(context.LogoutToken))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2239),
                        uri: SR.FormatID8000(SR.ID2239));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for resolving the client registration using the issuer and the audiences
        /// of the logout token, as recommended by OpenID Connect Back-Channel Logout 1.0, section 2.6.
        /// </summary>
        public sealed class ResolveClientRegistrationFromLogoutToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            private readonly OpenIddictClientService _service;

            public ResolveClientRegistrationFromLogoutToken(OpenIddictClientService service)
                => _service = service ?? throw new ArgumentNullException(nameof(service));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireLogoutTokenValidated>()
                    .UseSingletonHandler<ResolveClientRegistrationFromLogoutToken>()
                    .SetOrder(ValidateRequiredLogoutToken.Descriptor.Order + 100)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (string.IsNullOrEmpty(context.LogoutToken))
                {
                    return;
                }

                // Note: the logout token is read without being validated to determine which authorization
                // server issued it: the token is fully validated (including its signature) by a dedicated
                // handler using the signing keys of the authorization server attached to the registration.
                //
                // Encrypted logout tokens are decrypted using the encryption keys of the client to access
                // the issuer (OpenID Connect Back-Channel Logout 1.0, section 2.6, step 1).
                if (!TryReadJsonWebToken(context.Options, context.LogoutToken, out var token) ||
                    !Uri.TryCreate(token.Issuer, UriKind.Absolute, out Uri? issuer) || OpenIddictHelpers.IsImplicitFileUri(issuer))
                {
                    Reject(context, Errors.InvalidRequest, SR.ID2380);
                    return;
                }

                // If a registration was explicitly attached, only ensure it matches the issuer.
                if (context.Transaction.Registration is not null)
                {
                    if (!IssuerMatches(context.Registration.Issuer, issuer))
                    {
                        Reject(context, Errors.InvalidRequest, SR.ID2389);
                        return;
                    }
                }

                else
                {
                    // Note: multiple registrations can point to the same authorization server (e.g when using
                    // multiple client identifiers): in this case, the audiences are used to select the registration.
                    // If multiple registrations share the same issuer and client identifier, the registration whose
                    // back-channel logout URI matches the request URI is selected, if applicable.
                    var audiences = token.Audiences.ToHashSet(StringComparer.Ordinal);

                    var registrations = NarrowByRequestUri(context,
                        (await _service.GetClientRegistrationsAsync(context.CancellationToken))
                            .Where(registration => IssuerMatches(registration.Issuer, issuer) &&
                                !string.IsNullOrEmpty(registration.ClientId) && audiences.Contains(registration.ClientId))
                            .ToList(),
                        static registration => registration.BackchannelLogoutUri);

                    if (registrations is not [OpenIddictClientRegistration registration])
                    {
                        Reject(context, Errors.InvalidRequest, SR.ID2381);
                        return;
                    }

                    context.Registration = registration;
                }

                context.Issuer = context.Registration.Issuer;

                await ResolveConfigurationAsync(context);
            }
        }

        /// <summary>
        /// Contains the logic responsible for resolving the client registration using the "iss" parameter
        /// of the front-channel logout request, as defined by OpenID Connect Front-Channel Logout 1.0, section 3.
        /// </summary>
        public sealed class ResolveClientRegistrationFromFrontchannelLogoutRequest : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            private readonly OpenIddictClientService _service;

            public ResolveClientRegistrationFromFrontchannelLogoutRequest(OpenIddictClientService service)
                => _service = service ?? throw new ArgumentNullException(nameof(service));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireFrontchannelLogoutRequest>()
                    .UseSingletonHandler<ResolveClientRegistrationFromFrontchannelLogoutRequest>()
                    .SetOrder(ResolveClientRegistrationFromLogoutToken.Descriptor.Order + 50)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Note: the "iss" and "sid" parameters are sent by authorization servers when the client registration
                // requires them (which is the default for OpenIddict client registrations). If either is included,
                // both MUST be included. When they are not included, the request is only accepted if a unique client
                // registration that doesn't require them can be resolved, in which case the logout request only
                // applies to the session attached to the user agent for this registration.
                //
                // See https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout for more information.
                var value = (string?) context.Request?[Parameters.Iss];
                var session = (string?) context.Request?[Parameters.Sid];

                if (string.IsNullOrEmpty(value) && string.IsNullOrEmpty(session))
                {
                    IEnumerable<OpenIddictClientRegistration> source = context.Transaction.Registration is not null
                        ? [context.Registration]
                        : await _service.GetClientRegistrationsAsync(context.CancellationToken);

                    var candidates = NarrowByRequestUri(context,
                        source.Where(static registration => !registration.FrontchannelLogoutSessionRequired).ToList(),
                        static registration => registration.FrontchannelLogoutUri);

                    if (candidates is not [OpenIddictClientRegistration candidate])
                    {
                        Reject(context, Errors.InvalidRequest, SR.ID2387);
                        return;
                    }

                    context.Registration = candidate;
                    context.Issuer = candidate.Issuer;

                    await ResolveConfigurationAsync(context);
                    return;
                }

                if (string.IsNullOrEmpty(value) || string.IsNullOrEmpty(session) ||
                    !Uri.TryCreate(value, UriKind.Absolute, out Uri? issuer) || OpenIddictHelpers.IsImplicitFileUri(issuer))
                {
                    Reject(context, Errors.InvalidRequest, SR.ID2387);
                    return;
                }

                if (context.Transaction.Registration is not null)
                {
                    if (!IssuerMatches(context.Registration.Issuer, issuer))
                    {
                        Reject(context, Errors.InvalidRequest, SR.ID2390);
                        return;
                    }
                }

                else
                {
                    // Note: if multiple registrations share the same issuer, the registration
                    // whose front-channel logout URI matches the request URI is selected, if applicable.
                    var registrations = NarrowByRequestUri(context,
                        (await _service.GetClientRegistrationsAsync(context.CancellationToken))
                            .Where(registration => IssuerMatches(registration.Issuer, issuer))
                            .ToList(),
                        static registration => registration.FrontchannelLogoutUri);

                    if (registrations is not [OpenIddictClientRegistration registration])
                    {
                        Reject(context, Errors.InvalidRequest, SR.ID2388);
                        return;
                    }

                    context.Registration = registration;
                }

                context.Issuer = context.Registration.Issuer;
                context.SessionId = session;

                await ResolveConfigurationAsync(context);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the logout token resolved from the context.
        /// </summary>
        public sealed class ValidateLogoutToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ValidateLogoutToken(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireLogoutTokenValidated>()
                    .UseSingletonHandler<ValidateLogoutToken>()
                    .SetOrder(ResolveClientRegistrationFromLogoutToken.Descriptor.Order + 100)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (string.IsNullOrEmpty(context.LogoutToken))
                {
                    return;
                }

                var notification = new ValidateTokenContext(context.Transaction)
                {
                    // Note: for logout tokens, audience and lifetime validation is enforced by specialized handlers.
                    DisableAudienceValidation = true,
                    DisableLifetimeValidation = true,
                    DisablePresenterValidation = true,
                    Token = context.LogoutToken,
                    TokenFormat = TokenFormats.Private.JsonWebToken,
                    ValidTokenTypes = { TokenTypeIdentifiers.Private.LogoutToken }
                };

                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    if (context.RejectLogoutToken)
                    {
                        context.Logger.LogInformation(6564, SR.GetResourceString(SR.ID6564), notification.ErrorDescription);

                        context.Reject(
                            error: notification.Error ?? Errors.InvalidRequest,
                            description: notification.ErrorDescription,
                            uri: notification.ErrorUri);
                        return;
                    }

                    return;
                }

                context.LogoutTokenPrincipal = notification.Principal;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the well-known claims contained in the logout token,
        /// as required by OpenID Connect Back-Channel Logout 1.0, sections 2.4 and 2.6.
        /// </summary>
        public sealed class ValidateLogoutTokenWellknownClaims : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireLogoutTokenPrincipal>()
                    .UseSingletonHandler<ValidateLogoutTokenWellknownClaims>()
                    .SetOrder(ValidateLogoutToken.Descriptor.Order + 100)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(context.LogoutTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                foreach (var group in context.LogoutTokenPrincipal.Claims
                    .GroupBy(static claim => claim.Type, StringComparer.Ordinal)
                    .ToDictionary(static group => group.Key, group => group.ToList(), StringComparer.Ordinal)
                    .Where(static group => !ValidateClaimGroup(group.Key, group.Value)))
                {
                    Reject(context, Errors.InvalidRequest, SR.ID2382, group.Key);
                    return ValueTask.CompletedTask;
                }

                // Logout tokens MUST contain the "iss", "aud", "iat", "jti" and "events" claims.
                foreach (var claim in (ReadOnlySpan<string>) [Claims.Issuer, Claims.Audience, Claims.IssuedAt, Claims.JwtId, Claims.Events])
                {
                    if (!context.LogoutTokenPrincipal.HasClaim(claim))
                    {
                        Reject(context, Errors.InvalidRequest, SR.ID2382, claim);
                        return ValueTask.CompletedTask;
                    }
                }

                // The "events" claim MUST be a JSON object containing a "http://schemas.openid.net/event/backchannel-logout"
                // member whose value is a JSON object (typically empty, but additional members may be present).
                if (!ValidateEvents(context.LogoutTokenPrincipal.GetClaim(Claims.Events)))
                {
                    Reject(context, Errors.InvalidRequest, SR.ID2382, Claims.Events);
                    return ValueTask.CompletedTask;
                }

                // Logout tokens MUST NOT contain a "nonce" claim, which prevents
                // identity tokens from being used as logout tokens (and vice versa).
                if (context.LogoutTokenPrincipal.HasClaim(Claims.Nonce))
                {
                    Reject(context, Errors.InvalidRequest, SR.ID2383);
                    return ValueTask.CompletedTask;
                }

                context.Subject = context.LogoutTokenPrincipal.GetClaim(Claims.Subject);
                context.SessionId = context.LogoutTokenPrincipal.GetClaim(Claims.SessionId);

                // Logout tokens MUST contain a "sub" claim, a "sid" claim or both. The "sid" claim
                // is additionally required when the client registration requires session identifiers.
                if (string.IsNullOrEmpty(context.SessionId) &&
                   (string.IsNullOrEmpty(context.Subject) || context.Registration.BackchannelLogoutSessionRequired))
                {
                    Reject(context, Errors.InvalidRequest, SR.ID2382, Claims.SessionId);
                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;

                static bool ValidateClaimGroup(string name, List<Claim> values) => name switch
                {
                    // The following claims MUST be represented as unique strings.
                    Claims.Issuer or Claims.JwtId or Claims.SessionId or Claims.Subject
                        => values is [{ ValueType: ClaimValueTypes.String }],

                    // The following claims MUST be represented as unique strings or array of strings.
                    Claims.Audience => values.TrueForAll(static value => value.ValueType is ClaimValueTypes.String),

                    // The following claims MUST be represented as unique numeric dates.
                    Claims.ExpiresAt or Claims.IssuedAt or Claims.NotBefore
                        => values is [{ ValueType: ClaimValueTypes.Integer    or ClaimValueTypes.Integer32 or
                                                   ClaimValueTypes.Integer64  or ClaimValueTypes.Double    or
                                                   ClaimValueTypes.UInteger32 or ClaimValueTypes.UInteger64 }],

                    // The "events" claim MUST be represented as a unique JSON object.
                    Claims.Events => values is [{ ValueType: JsonClaimValueTypes.Json }],

                    // Claims that are not in the well-known list can be of any type.
                    _ => true
                };

                static bool ValidateEvents(string? value)
                {
                    if (string.IsNullOrEmpty(value))
                    {
                        return false;
                    }

                    try
                    {
                        using var document = JsonDocument.Parse(value);

                        return document.RootElement.ValueKind is JsonValueKind.Object &&
                               document.RootElement.TryGetProperty(SecurityEventTypes.BackchannelLogout, out var member) &&
                               member.ValueKind is JsonValueKind.Object;
                    }

                    catch (JsonException)
                    {
                        return false;
                    }
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the audiences of the logout token.
        /// </summary>
        public sealed class ValidateLogoutTokenAudience : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireLogoutTokenPrincipal>()
                    .UseSingletonHandler<ValidateLogoutTokenAudience>()
                    .SetOrder(ValidateLogoutTokenWellknownClaims.Descriptor.Order + 100)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(context.LogoutTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                // The client identifier of the application MUST be included in the audiences of the logout token.
                //
                // See https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation for more information.
                var audiences = context.LogoutTokenPrincipal.GetClaims(Claims.Audience);
                if (string.IsNullOrEmpty(context.Registration.ClientId) ||
                    !audiences.Contains(context.Registration.ClientId, StringComparer.Ordinal))
                {
                    Reject(context, Errors.InvalidRequest, SR.ID2384);
                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the "exp" and "iat" claims of the logout token.
        /// </summary>
        public sealed class ValidateLogoutTokenLifetime : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireLogoutTokenPrincipal>()
                    .UseSingletonHandler<ValidateLogoutTokenLifetime>()
                    .SetOrder(ValidateLogoutTokenAudience.Descriptor.Order + 100)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(context.LogoutTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                var now = context.Options.TimeProvider.GetUtcNow();
                var age = context.LogoutTokenMaximumAge ?? context.Options.LogoutTokenMaximumAge;
                var skew = context.Registration.TokenValidationParameters.ClockSkew;

                if (!TryGetDate(context.LogoutTokenPrincipal, Claims.IssuedAt, out var issuedAt) ||
                    !TryGetDate(context.LogoutTokenPrincipal, Claims.ExpiresAt, out var expiresAt))
                {
                    Reject(context, Errors.InvalidRequest, SR.ID2385);
                    return ValueTask.CompletedTask;
                }

                // Reject expired logout tokens (the "exp" claim was not required by early drafts of the specification).
                if (expiresAt is not null && expiresAt.Value + skew < now)
                {
                    Reject(context, Errors.InvalidRequest, SR.ID2385);
                    return ValueTask.CompletedTask;
                }

                // While not required by the specification, the "nbf" claim is a registered JWT claim that
                // MUST be honored when present (RFC 7519, section 4.1.5): reject tokens that are not valid yet.
                if (!TryGetDate(context.LogoutTokenPrincipal, Claims.NotBefore, out var notBefore) ||
                    (notBefore is not null && notBefore.Value > now + skew))
                {
                    Reject(context, Errors.InvalidRequest, SR.ID2385);
                    return ValueTask.CompletedTask;
                }

                // The "iat" claim is validated the same way it's validated for identity tokens: logout tokens issued
                // too far in the future are rejected. Since the replay cache only retains token identifiers for a
                // limited period, logout tokens that don't have an expiration date are only accepted if they were
                // issued during this period, which prevents them from being replayed once their identifier is evicted.
                //
                // See https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation for more information.
                if (issuedAt!.Value > now + age + skew || (expiresAt is null && issuedAt.Value + age + skew < now))
                {
                    Reject(context, Errors.InvalidRequest, SR.ID2385);
                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting logout tokens whose identifier was already used.
        /// When an <see cref="IDistributedCache"/> implementation is registered, it is used to store the
        /// token identifiers. Otherwise, the identifiers are stored in memory by this handler instance.
        /// </summary>
        /// <remarks>
        /// Note: <see cref="IDistributedCache"/> doesn't offer an atomic "add if absent" operation: when a distributed
        /// cache is used, replay detection is best-effort and concurrent deliveries of the same token may be accepted.
        /// If the sessions cannot be terminated by the back-channel logout endpoint, the identifier is released.
        /// </remarks>
        public sealed class RedeemLogoutTokenIdentifier : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            private readonly ConcurrentDictionary<string, DateTimeOffset> _identifiers = new(StringComparer.Ordinal);

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireLogoutTokenPrincipal>()
                    .UseSingletonHandler<RedeemLogoutTokenIdentifier>()
                    .SetOrder(ValidateLogoutTokenLifetime.Descriptor.Order + 100)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(context.LogoutTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));
                Debug.Assert(context.Registration.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));

                var identifier = context.LogoutTokenPrincipal.GetClaim(Claims.JwtId);
                if (string.IsNullOrEmpty(identifier) ||
                    !TryGetDate(context.LogoutTokenPrincipal, Claims.IssuedAt, out var issuedAt) || issuedAt is null ||
                    !TryGetDate(context.LogoutTokenPrincipal, Claims.ExpiresAt, out var expiresAt))
                {
                    Reject(context, Errors.InvalidRequest, SR.ID2382, Claims.JwtId);
                    return;
                }

                // Note: the identifier is kept until the token can no longer be accepted (i.e until it expires or,
                // for tokens without an expiration date, until the end of the accepted "iat" window), plus the clock
                // skew and at least for the maximum age configured in the options.
                var now = context.Options.TimeProvider.GetUtcNow();
                var skew = context.Registration.TokenValidationParameters.ClockSkew;
                var age = context.LogoutTokenMaximumAge ?? context.Options.LogoutTokenMaximumAge;
                var expiration = now + age;
                var limit = (expiresAt ?? issuedAt.Value + age) + skew;
                if (limit > expiration)
                {
                    expiration = limit;
                }

                // Note: identifiers are only unique per issuer (the signature of the logout token was already validated).
                var key = string.Concat("openiddict-client-logout-token:", context.Registration.Issuer.AbsoluteUri, " ", identifier);

                if (context.ServiceProvider.GetService<IDistributedCache>() is IDistributedCache cache)
                {
                    if (await cache.GetAsync(key, context.CancellationToken) is not null)
                    {
                        Reject(context, Errors.InvalidRequest, SR.ID2386);
                        return;
                    }

                    await cache.SetAsync(key, [1], new DistributedCacheEntryOptions
                    {
                        AbsoluteExpiration = expiration
                    }, context.CancellationToken);

                    context.Transaction.SetProperty<Func<CancellationToken, ValueTask>>(LogoutTokenIdentifierReleaseProperty,
                        async cancellationToken => await cache.RemoveAsync(key, cancellationToken));

                    return;
                }

                foreach (var entry in _identifiers)
                {
                    if (entry.Value <= now)
                    {
                        _identifiers.TryRemove(entry.Key, out _);
                    }
                }

                if (!_identifiers.TryAdd(key, expiration))
                {
                    Reject(context, Errors.InvalidRequest, SR.ID2386);
                    return;
                }

                context.Transaction.SetProperty<Func<CancellationToken, ValueTask>>(LogoutTokenIdentifierReleaseProperty, cancellationToken =>
                {
                    _identifiers.TryRemove(key, out _);
                    return ValueTask.CompletedTask;
                });
            }
        }

        /// <summary>
        /// Contains the logic responsible for resolving the "session_state" parameter returned as part of authorization
        /// responses by the authorization servers supporting OpenID Connect Session Management 1.0 (section 3).
        /// </summary>
        public sealed class ResolveSessionState : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireRedirectionRequest>()
                    .UseSingletonHandler<ResolveSessionState>()
                    .SetOrder(ResolveValidatedFrontchannelTokens.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                context.SessionState ??= (string?) context.Request?[Parameters.SessionState];

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the logout and session management
        /// metadata (e.g "backchannel_logout_supported" or "check_session_iframe") from the discovery document.
        /// </summary>
        public sealed class ExtractLogoutMetadata : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractLogoutMetadata>()
                    .SetOrder(Discovery.ExtractRequestObjectRequirements.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                foreach (var name in (ReadOnlySpan<string>)
                [
                    Metadata.BackchannelLogoutSessionSupported,
                    Metadata.BackchannelLogoutSupported,
                    Metadata.FrontchannelLogoutSessionSupported,
                    Metadata.FrontchannelLogoutSupported
                ])
                {
                    var parameter = context.Response[name];
                    if (parameter is null)
                    {
                        continue;
                    }

                    // The following parameters MUST be formatted as booleans.
                    if (((JsonElement) parameter.Value).ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2107(name),
                            uri: SR.FormatID8000(SR.ID2107));

                        return ValueTask.CompletedTask;
                    }
                }

                context.Configuration.BackchannelLogoutSessionSupported = (bool?) context.Response[Metadata.BackchannelLogoutSessionSupported];
                context.Configuration.BackchannelLogoutSupported = (bool?) context.Response[Metadata.BackchannelLogoutSupported];
                context.Configuration.FrontchannelLogoutSessionSupported = (bool?) context.Response[Metadata.FrontchannelLogoutSessionSupported];
                context.Configuration.FrontchannelLogoutSupported = (bool?) context.Response[Metadata.FrontchannelLogoutSupported];

                var iframe = context.Response[Metadata.CheckSessionIframe];
                if (iframe is not null)
                {
                    if (((JsonElement) iframe.Value).ValueKind is not JsonValueKind.String ||
                        !Uri.TryCreate((string?) iframe, UriKind.Absolute, out Uri? uri) || OpenIddictHelpers.IsImplicitFileUri(uri))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2100(Metadata.CheckSessionIframe),
                            uri: SR.FormatID8000(SR.ID2100));

                        return ValueTask.CompletedTask;
                    }

                    context.Configuration.CheckSessionIframe = uri;
                }

                return ValueTask.CompletedTask;
            }
        }

        private static async ValueTask RemoveSessionsAsync(BaseContext context,
            List<IOpenIddictClientSessionStore> stores, string? subject, string? session)
        {
            Debug.Assert(context.Registration is not null, SR.GetResourceString(SR.ID4013));

            foreach (var store in stores)
            {
                var count = await store.RemoveSessionsAsync(context.Registration, subject, session, context.CancellationToken);

                context.Logger.LogInformation(6565, SR.GetResourceString(SR.ID6565), count,
                    store.GetType().FullName, context.Registration.RegistrationId, subject, session);
            }
        }

        private static async ValueTask ResolveConfigurationAsync(ProcessAuthenticationContext context)
        {
            if (context.Transaction.Configuration is not null)
            {
                return;
            }

            if (context.Registration.ConfigurationManager is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0422));
            }

            try
            {
                context.Configuration = await context.Registration.ConfigurationManager
                    .GetConfigurationAsync(context.CancellationToken)
                    .WaitAsync(context.CancellationToken)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception) &&
                exception is not OperationCanceledException)
            {
                context.Logger.LogError(6219, exception, SR.GetResourceString(SR.ID6219));

                context.Reject(
                    error: Errors.ServerError,
                    description: SR.GetResourceString(SR.ID2170),
                    uri: SR.FormatID8000(SR.ID2170));
            }
        }

        private const string LogoutTokenIdentifierReleaseProperty = ".logout_token_identifier_release";

        private static async ValueTask ReleaseLogoutTokenIdentifierAsync(
            OpenIddictClientTransaction transaction, CancellationToken cancellationToken)
        {
            var release = transaction.GetProperty<Func<CancellationToken, ValueTask>>(LogoutTokenIdentifierReleaseProperty);
            if (release is null)
            {
                return;
            }

            transaction.SetProperty<Func<CancellationToken, ValueTask>>(LogoutTokenIdentifierReleaseProperty, null);

            await release(cancellationToken);
        }

        private static List<OpenIddictClientRegistration> NarrowByRequestUri(BaseContext context,
            List<OpenIddictClientRegistration> registrations, Func<OpenIddictClientRegistration, Uri?> selector)
        {
            if (registrations.Count < 2 || context.RequestUri is not { IsAbsoluteUri: true } request)
            {
                return registrations;
            }

            var matches = registrations.FindAll(registration => selector(registration) switch
            {
                { IsAbsoluteUri: true } uri => UriMatches(uri, request),

                Uri uri when context.BaseUri is { IsAbsoluteUri: true } => OpenIddictHelpers.CreateAbsoluteUri(context.BaseUri, uri) is Uri absolute &&
                    !OpenIddictHelpers.IsImplicitFileUri(absolute) &&
                     OpenIddictHelpers.IsBaseOf(context.BaseUri, absolute) && UriMatches(absolute, request),

                _ => false
            });

            return matches.Count is 0 ? registrations : matches;

            // Note: paths that only differ by their casing or by a trailing slash are considered equivalent,
            // which matches the logic used to infer the endpoint type from the request URI.
            static bool UriMatches(Uri left, Uri right) =>
                string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(left.Host, right.Host, StringComparison.OrdinalIgnoreCase) &&
                left.Port == right.Port &&
                string.Equals(left.AbsolutePath.TrimEnd('/'), right.AbsolutePath.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);
        }

        private static bool IssuerMatches(Uri? left, Uri right)
            // Note: issuers that only differ by a trailing slash are considered equivalent.
            => left is { IsAbsoluteUri: true } && string.Equals(
                left.AbsoluteUri.TrimEnd('/'), right.AbsoluteUri.TrimEnd('/'), StringComparison.Ordinal);

        private static void Reject(ProcessAuthenticationContext context, string error, string identifier, string? argument = null)
        {
            var description = argument is null
                ? SR.GetResourceString(identifier)
                : string.Format(CultureInfo.CurrentCulture, SR.GetResourceString(identifier), argument);

            context.Logger.LogInformation(6564, SR.GetResourceString(SR.ID6564), description);

            context.Reject(error: error, description: description, uri: SR.FormatID8000(identifier));
        }

        private static bool TryGetDate(ClaimsPrincipal principal, string type, out DateTimeOffset? date)
        {
            var value = principal.GetClaim(type);
            if (string.IsNullOrEmpty(value))
            {
                date = null;
                return true;
            }

            // Note: numeric dates can be represented as integers or decimal numbers.
            if (!double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds) ||
                double.IsNaN(seconds) || double.IsInfinity(seconds) || seconds < -62135596800 || seconds > 253402300799)
            {
                date = null;
                return false;
            }

            date = DateTimeOffset.FromUnixTimeSeconds((long) Math.Floor(seconds));
            return true;
        }

        private static bool TryReadJsonWebToken(OpenIddictClientOptions options, string token, out JsonWebToken result)
        {
            var handler = options.JsonWebTokenHandler;
            if (!handler.CanReadToken(token))
            {
                result = null!;
                return false;
            }

            try
            {
                result = handler.ReadJsonWebToken(token);

                // If the token is encrypted, decrypt it using the encryption keys of the client to access its claims.
                if (result.IsEncrypted)
                {
                    var keys = options.TokenValidationParameters.TokenDecryptionKeys;
                    if (keys is null || !keys.Any())
                    {
                        result = null!;
                        return false;
                    }

                    result = handler.ReadJsonWebToken(handler.DecryptToken(result, new TokenValidationParameters
                    {
                        TokenDecryptionKeys = keys
                    }));
                }

                return true;
            }

            // Note: CanReadToken() only checks the overall format of the token: tokens whose segments
            // are not valid base64url-encoded JSON documents are rejected when they are actually read.
            catch (Exception exception) when (exception is ArgumentException or SecurityTokenException)
            {
                result = null!;
                return false;
            }
        }
    }
}
