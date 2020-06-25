/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using SR = OpenIddict.Abstractions.Resources.OpenIddictResources;

namespace OpenIddict.Server
{
    public static partial class OpenIddictServerHandlers
    {
        public static class Session
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Logout request top-level processing:
                 */
                ExtractLogoutRequest.Descriptor,
                ValidateLogoutRequest.Descriptor,
                HandleLogoutRequest.Descriptor,
                ApplyLogoutResponse<ProcessErrorContext>.Descriptor,
                ApplyLogoutResponse<ProcessRequestContext>.Descriptor,
                ApplyLogoutResponse<ProcessSignOutContext>.Descriptor,

                /*
                 * Logout request validation:
                 */
                ValidatePostLogoutRedirectUriParameter.Descriptor,
                ValidateClientPostLogoutRedirectUri.Descriptor,

                /*
                 * Logout response processing:
                 */
                AttachPostLogoutRedirectUri.Descriptor,
                AttachResponseState.Descriptor);

            /// <summary>
            /// Contains the logic responsible of extracting logout requests and invoking the corresponding event handlers.
            /// </summary>
            public class ExtractLogoutRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ExtractLogoutRequest([NotNull] IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .AddFilter<RequireLogoutRequest>()
                        .UseScopedHandler<ExtractLogoutRequest>()
                        .SetOrder(100_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new ExtractLogoutRequestContext(context.Transaction);
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

                    if (notification.Request == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1049));
                    }

                    context.Logger.LogInformation("The logout request was successfully extracted: {Request}.", notification.Request);
                }
            }

            /// <summary>
            /// Contains the logic responsible of validating logout requests and invoking the corresponding event handlers.
            /// </summary>
            public class ValidateLogoutRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ValidateLogoutRequest([NotNull] IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .AddFilter<RequireLogoutRequest>()
                        .UseScopedHandler<ValidateLogoutRequest>()
                        .SetOrder(ExtractLogoutRequest.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new ValidateLogoutRequestContext(context.Transaction);
                    await _dispatcher.DispatchAsync(notification);

                    // Store the context object in the transaction so it can be later retrieved by handlers
                    // that want to access the redirect_uri without triggering a new validation process.
                    context.Transaction.SetProperty(typeof(ValidateLogoutRequestContext).FullName, notification);

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

                    context.Logger.LogInformation("The logout request was successfully validated.");
                }
            }

            /// <summary>
            /// Contains the logic responsible of handling logout requests and invoking the corresponding event handlers.
            /// </summary>
            public class HandleLogoutRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public HandleLogoutRequest([NotNull] IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .AddFilter<RequireLogoutRequest>()
                        .UseScopedHandler<HandleLogoutRequest>()
                        .SetOrder(ValidateLogoutRequest.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new HandleLogoutRequestContext(context.Transaction);
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

                    if (notification.IsSignOutTriggered)
                    {
                        var @event = new ProcessSignOutContext(context.Transaction)
                        {
                            Response = new OpenIddictResponse()
                        };

                        await _dispatcher.DispatchAsync(@event);

                        if (@event.IsRequestHandled)
                        {
                            context.HandleRequest();
                            return;
                        }

                        else if (@event.IsRequestSkipped)
                        {
                            context.SkipRequest();
                            return;
                        }

                        else if (@event.IsRejected)
                        {
                            context.Reject(
                                error: @event.Error ?? Errors.InvalidRequest,
                                description: @event.ErrorDescription,
                                uri: @event.ErrorUri);
                            return;
                        }
                    }

                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1050));
                }
            }

            /// <summary>
            /// Contains the logic responsible of processing sign-in responses and invoking the corresponding event handlers.
            /// </summary>
            public class ApplyLogoutResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ApplyLogoutResponse([NotNull] IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .AddFilter<RequireLogoutRequest>()
                        .UseScopedHandler<ApplyLogoutResponse<TContext>>()
                        .SetOrder(int.MaxValue - 100_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] TContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new ApplyLogoutResponseContext(context.Transaction);
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

                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1051));
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting logout requests that specify an invalid post_logout_redirect_uri parameter.
            /// </summary>
            public class ValidatePostLogoutRedirectUriParameter : IOpenIddictServerHandler<ValidateLogoutRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateLogoutRequestContext>()
                        .UseSingletonHandler<ValidatePostLogoutRedirectUriParameter>()
                        .SetOrder(int.MinValue + 100_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateLogoutRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (string.IsNullOrEmpty(context.PostLogoutRedirectUri))
                    {
                        return default;
                    }

                    // If an optional post_logout_redirect_uri was provided, validate it.
                    if (!Uri.TryCreate(context.PostLogoutRedirectUri, UriKind.Absolute, out Uri uri) || !uri.IsWellFormedOriginalString())
                    {
                        context.Logger.LogError("The logout request was rejected because the specified post_logout_redirect_uri " +
                                                "was not a valid absolute URL: {PostLogoutRedirectUri}.", context.PostLogoutRedirectUri);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: context.Localizer[SR.ID3030, Parameters.PostLogoutRedirectUri]);

                        return default;
                    }

                    if (!string.IsNullOrEmpty(uri.Fragment))
                    {
                        context.Logger.LogError("The logout request was rejected because the 'post_logout_redirect_uri' contained " +
                                                "a URL fragment: {PostLogoutRedirectUri}.", context.PostLogoutRedirectUri);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: context.Localizer[SR.ID3031, Parameters.PostLogoutRedirectUri]);

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting logout requests that use an invalid redirect_uri.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientPostLogoutRedirectUri : IOpenIddictServerHandler<ValidateLogoutRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientPostLogoutRedirectUri() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

                public ValidateClientPostLogoutRedirectUri([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateLogoutRequestContext>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .AddFilter<RequirePostLogoutRedirectUriParameter>()
                        .UseScopedHandler<ValidateClientPostLogoutRedirectUri>()
                        .SetOrder(ValidatePostLogoutRedirectUriParameter.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateLogoutRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (!await ValidatePostLogoutRedirectUriAsync(context.PostLogoutRedirectUri))
                    {
                        context.Logger.LogError("The logout request was rejected because the specified post_logout_redirect_uri " +
                                                "was unknown: {PostLogoutRedirectUri}.", context.PostLogoutRedirectUri);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: context.Localizer[SR.ID3052, Parameters.PostLogoutRedirectUri]);

                        return;
                    }

                    async ValueTask<bool> ValidatePostLogoutRedirectUriAsync(string address)
                    {
                        // To be considered valid, a post_logout_redirect_uri must correspond to an existing client application
                        // that was granted the ept:logout permission, unless endpoint permissions checking was explicitly disabled.

                        await foreach (var application in _applicationManager.FindByPostLogoutRedirectUriAsync(address))
                        {
                            if (context.Options.IgnoreEndpointPermissions ||
                                await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.Logout))
                            {
                                return true;
                            }
                        }

                        return false;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of inferring the redirect URL
            /// used to send the response back to the client application.
            /// </summary>
            public class AttachPostLogoutRedirectUri : IOpenIddictServerHandler<ApplyLogoutResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyLogoutResponseContext>()
                        .UseSingletonHandler<AttachPostLogoutRedirectUri>()
                        .SetOrder(int.MinValue + 100_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ApplyLogoutResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.Request == null)
                    {
                        return default;
                    }

                    var notification = context.Transaction.GetProperty<ValidateLogoutRequestContext>(
                        typeof(ValidateLogoutRequestContext).FullName);

                    // Note: at this stage, the validated redirect URI property may be null (e.g if
                    // an error is returned from the ExtractLogoutRequest/ValidateLogoutRequest events).
                    if (notification != null && !notification.IsRejected)
                    {
                        context.PostLogoutRedirectUri = notification.PostLogoutRedirectUri;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the state to the response.
            /// </summary>
            public class AttachResponseState : IOpenIddictServerHandler<ApplyLogoutResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyLogoutResponseContext>()
                        .UseSingletonHandler<AttachResponseState>()
                        .SetOrder(AttachPostLogoutRedirectUri.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ApplyLogoutResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Attach the request state to the logout response.
                    if (string.IsNullOrEmpty(context.Response.State))
                    {
                        context.Response.State = context.Request?.State;
                    }

                    return default;
                }
            }
        }
    }
}
