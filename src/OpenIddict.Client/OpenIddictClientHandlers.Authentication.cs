/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Client;

public static partial class OpenIddictClientHandlers
{
    public static class Authentication
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authorization request top-level processing:
             */
            PrepareAuthorizationRequest.Descriptor,
            ApplyAuthorizationRequest.Descriptor,

            /*
             * Authorization request preparation:
             */
            NormalizeResponseModeParameter.Descriptor,

            /*
             * Authorization request processing:
             */
            AttachAuthorizationEndpoint.Descriptor,

            /*
             * Redirection request top-level processing:
             */
            ExtractRedirectionRequest.Descriptor,
            ValidateRedirectionRequest.Descriptor,
            HandleRedirectionRequest.Descriptor,
            ApplyRedirectionResponse<ProcessErrorContext>.Descriptor,
            ApplyRedirectionResponse<ProcessRequestContext>.Descriptor,

            /*
             * Redirection request validation:
             */
            ValidateTokens.Descriptor);

        /// <summary>
        /// Contains the logic responsible for preparing authorization requests and invoking the corresponding event handlers.
        /// </summary>
        public class PrepareAuthorizationRequest : IOpenIddictClientHandler<ProcessChallengeContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public PrepareAuthorizationRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireInteractiveGrantType>()
                    .UseScopedHandler<PrepareAuthorizationRequest>()
                    .SetOrder(int.MaxValue - 100_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessChallengeContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new PrepareAuthorizationRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                else if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for applying authorization requests and invoking the corresponding event handlers.
        /// </summary>
        public class ApplyAuthorizationRequest : IOpenIddictClientHandler<ProcessChallengeContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ApplyAuthorizationRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireInteractiveGrantType>()
                    .UseScopedHandler<ApplyAuthorizationRequest>()
                    .SetOrder(PrepareAuthorizationRequest.Descriptor.Order + 1_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessChallengeContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ApplyAuthorizationRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                else if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the address of the authorization request to the request.
        /// </summary>
        public class AttachAuthorizationEndpoint : IOpenIddictClientHandler<ApplyAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyAuthorizationRequestContext>()
                    .UseSingletonHandler<AttachAuthorizationEndpoint>()
                    .SetOrder(int.MinValue + 100_000)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Ensure the authorization endpoint is present and is a valid absolute URL.
                if (context.Configuration.AuthorizationEndpoint is not { IsAbsoluteUri: true } ||
                   !context.Configuration.AuthorizationEndpoint.IsWellFormedOriginalString())
                {
                    throw new InvalidOperationException(SR.FormatID0301(Metadata.AuthorizationEndpoint));
                }

                context.AuthorizationEndpoint = context.Configuration.AuthorizationEndpoint.AbsoluteUri;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting redirection requests and invoking the corresponding event handlers.
        /// </summary>
        public class ExtractRedirectionRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ExtractRedirectionRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireRedirectionRequest>()
                    .UseScopedHandler<ExtractRedirectionRequest>()
                    .SetOrder(100_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ExtractRedirectionRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                else if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                else if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                if (notification.Request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0302));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6178), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating redirection requests and invoking the corresponding event handlers.
        /// </summary>
        public class ValidateRedirectionRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ValidateRedirectionRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireRedirectionRequest>()
                    .UseScopedHandler<ValidateRedirectionRequest>()
                    .SetOrder(ExtractRedirectionRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ValidateRedirectionRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                else if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                else if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6179));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling redirection requests and invoking the corresponding event handlers.
        /// </summary>
        public class HandleRedirectionRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public HandleRedirectionRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireRedirectionRequest>()
                    .UseScopedHandler<HandleRedirectionRequest>()
                    .SetOrder(ValidateRedirectionRequest.Descriptor.Order + 1_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new HandleRedirectionRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                else if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                else if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6180));
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing redirection responses and invoking the corresponding event handlers.
        /// </summary>
        public class ApplyRedirectionResponse<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ApplyRedirectionResponse(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireRedirectionRequest>()
                    .UseScopedHandler<ApplyRedirectionResponse<TContext>>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ApplyRedirectionResponseContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                else if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0303));
            }
        }

        /// <summary>
        /// Contains the logic responsible for removing the response mode parameter from the
        /// request if it corresponds to the default mode for the selected response type.
        /// </summary>
        public class NormalizeResponseModeParameter : IOpenIddictClientHandler<PrepareAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareAuthorizationRequestContext>()
                    .UseSingletonHandler<NormalizeResponseModeParameter>()
                    .SetOrder(int.MinValue + 100_000)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // When the response mode corresponds to the default mode assigned to the selected
                // response type, the specification explicitly recommends omitting the response mode.
                // As such, this handler is expected to remove the mode parameter in the following cases:
                //   - Authorization code flow: response_mode=query.
                //   - Hybrid flow: response_mode=fragment.
                //   - Implicit flow: response_mode=fragment.
                //
                // For more information, read
                // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes.
                //
                if (!string.IsNullOrEmpty(context.Request.ResponseMode) &&
                   (context.Request.IsAuthorizationCodeFlow() && context.Request.IsQueryResponseMode())    ||
                   (context.Request.IsHybridFlow()            && context.Request.IsFragmentResponseMode()) ||
                   (context.Request.IsImplicitFlow()          && context.Request.IsFragmentResponseMode()))
                {
                    context.Request.ResponseMode = null;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting redirection requests that don't
        /// specify a valid access token, authorization code, identity token or state token.
        /// </summary>
        public class ValidateTokens : IOpenIddictClientHandler<ValidateRedirectionRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ValidateTokens(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateRedirectionRequestContext>()
                    .UseScopedHandler<ValidateTokens>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateRedirectionRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

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

                else if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                else if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                // Attach the security principals extracted from the tokens to the validation context.
                context.Principal = notification.FrontchannelIdentityTokenPrincipal;
                context.StateTokenPrincipal = notification.StateTokenPrincipal;
            }
        }
    }
}
