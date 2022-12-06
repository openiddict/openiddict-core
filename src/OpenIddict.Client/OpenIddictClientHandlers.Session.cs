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
    public static class Session
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Logout request top-level processing:
             */
            PrepareLogoutRequest.Descriptor,
            ApplyLogoutRequest.Descriptor,

            /*
             * Logout request processing:
             */
            AttachLogoutEndpoint.Descriptor,

            /*
             * Post-logout redirection request top-level processing:
             */
            ExtractPostLogoutRedirectionRequest.Descriptor,
            ValidatePostLogoutRedirectionRequest.Descriptor,
            HandlePostLogoutRedirectionRequest.Descriptor,
            ApplyPostLogoutRedirectionResponse<ProcessErrorContext>.Descriptor,
            ApplyPostLogoutRedirectionResponse<ProcessRequestContext>.Descriptor,

            /*
             * Post-logout redirection request validation:
             */
            ValidateTokens.Descriptor);

        /// <summary>
        /// Contains the logic responsible for preparing authorization requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class PrepareLogoutRequest : IOpenIddictClientHandler<ProcessSignOutContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public PrepareLogoutRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                    .UseScopedHandler<PrepareLogoutRequest>()
                    .SetOrder(int.MaxValue - 100_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessSignOutContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new PrepareLogoutRequestContext(context.Transaction);
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
        public sealed class ApplyLogoutRequest : IOpenIddictClientHandler<ProcessSignOutContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ApplyLogoutRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                    .UseScopedHandler<ApplyLogoutRequest>()
                    .SetOrder(PrepareLogoutRequest.Descriptor.Order + 1_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessSignOutContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ApplyLogoutRequestContext(context.Transaction);
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
        /// Contains the logic responsible for attaching the URI of the authorization request to the request.
        /// </summary>
        public sealed class AttachLogoutEndpoint : IOpenIddictClientHandler<ApplyLogoutRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyLogoutRequestContext>()
                    .UseSingletonHandler<AttachLogoutEndpoint>()
                    .SetOrder(int.MinValue + 100_000)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyLogoutRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Ensure the end session endpoint is present and is a valid absolute URI.
                if (context.Configuration.EndSessionEndpoint is not { IsAbsoluteUri: true } ||
                   !context.Configuration.EndSessionEndpoint.IsWellFormedOriginalString())
                {
                    throw new InvalidOperationException(SR.FormatID0301(Metadata.EndSessionEndpoint));
                }

                context.EndSessionEndpoint = context.Configuration.EndSessionEndpoint.AbsoluteUri;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting redirection requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractPostLogoutRedirectionRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ExtractPostLogoutRedirectionRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequirePostLogoutRedirectionRequest>()
                    .UseScopedHandler<ExtractPostLogoutRedirectionRequest>()
                    .SetOrder(100_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ExtractPostLogoutRedirectionRequestContext(context.Transaction);
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6199), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating redirection requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidatePostLogoutRedirectionRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ValidatePostLogoutRedirectionRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequirePostLogoutRedirectionRequest>()
                    .UseScopedHandler<ValidatePostLogoutRedirectionRequest>()
                    .SetOrder(ExtractPostLogoutRedirectionRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ValidatePostLogoutRedirectionRequestContext(context.Transaction);
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6200));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling redirection requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandlePostLogoutRedirectionRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public HandlePostLogoutRedirectionRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequirePostLogoutRedirectionRequest>()
                    .UseScopedHandler<HandlePostLogoutRedirectionRequest>()
                    .SetOrder(ValidatePostLogoutRedirectionRequest.Descriptor.Order + 1_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new HandlePostLogoutRedirectionRequestContext(context.Transaction);
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6201));
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing redirection responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyPostLogoutRedirectionResponse<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ApplyPostLogoutRedirectionResponse(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequirePostLogoutRedirectionRequest>()
                    .UseScopedHandler<ApplyPostLogoutRedirectionResponse<TContext>>()
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

                var notification = new ApplyPostLogoutRedirectionResponseContext(context.Transaction);
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
        /// Contains the logic responsible for rejecting redirection requests that don't
        /// specify a valid access token, authorization code, identity token or state token.
        /// </summary>
        public sealed class ValidateTokens : IOpenIddictClientHandler<ValidatePostLogoutRedirectionRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ValidateTokens(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidatePostLogoutRedirectionRequestContext>()
                    .UseScopedHandler<ValidateTokens>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidatePostLogoutRedirectionRequestContext context)
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
