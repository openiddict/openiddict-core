/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;

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
                ApplyLogoutResponse<ProcessErrorResponseContext>.Descriptor,
                ApplyLogoutResponse<ProcessRequestContext>.Descriptor,
                ApplyLogoutResponse<ProcessSignoutResponseContext>.Descriptor,

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
                private readonly IOpenIddictServerProvider _provider;

                public ExtractLogoutRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<ExtractLogoutRequest>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async Task HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Logout)
                    {
                        return;
                    }

                    var notification = new ExtractLogoutRequestContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("The logout request was not correctly extracted. To extract logout requests, ")
                            .Append("create a class implementing 'IOpenIddictServerHandler<ExtractLogoutRequestContext>' ")
                            .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                            .ToString());
                    }

                    context.Logger.LogInformation("The logout request was successfully extracted: {Request}.", notification.Request);
                }
            }

            /// <summary>
            /// Contains the logic responsible of validating logout requests and invoking the corresponding event handlers.
            /// </summary>
            public class ValidateLogoutRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public ValidateLogoutRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<ValidateLogoutRequest>()
                        .SetOrder(ExtractLogoutRequest.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async Task HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Logout)
                    {
                        return;
                    }

                    var notification = new ValidateLogoutRequestContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    if (!string.IsNullOrEmpty(notification.PostLogoutRedirectUri))
                    {
                        // Store the validated post_logout_redirect_uri as an environment property.
                        context.Transaction.Properties[Properties.PostLogoutRedirectUri] = notification.PostLogoutRedirectUri;
                    }

                    context.Logger.LogInformation("The logout request was successfully validated.");
                }
            }

            /// <summary>
            /// Contains the logic responsible of handling logout requests and invoking the corresponding event handlers.
            /// </summary>
            public class HandleLogoutRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public HandleLogoutRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<HandleLogoutRequest>()
                        .SetOrder(ValidateLogoutRequest.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async Task HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Logout)
                    {
                        return;
                    }

                    var notification = new HandleLogoutRequestContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    if (notification.IsLogoutAllowed)
                    {
                        var @event = new ProcessSignoutResponseContext(context.Transaction)
                        {
                            Response = new OpenIddictResponse()
                        };

                        await _provider.DispatchAsync(@event);

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
                    }

                    throw new InvalidOperationException(new StringBuilder()
                        .Append("The logout request was not handled. To handle logout requests, ")
                        .Append("create a class implementing 'IOpenIddictServerHandler<HandleLogoutRequestContext>' ")
                        .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                        .Append("Alternatively, enable the pass-through mode to handle them at a later stage.")
                        .ToString());
                }
            }

            /// <summary>
            /// Contains the logic responsible of processing sign-in responses and invoking the corresponding event handlers.
            /// </summary>
            public class ApplyLogoutResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
            {
                private readonly IOpenIddictServerProvider _provider;

                public ApplyLogoutResponse([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .UseScopedHandler<ApplyLogoutResponse<TContext>>()
                        .SetOrder(int.MaxValue - 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async Task HandleAsync([NotNull] TContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Logout)
                    {
                        return;
                    }

                    var notification = new ApplyLogoutResponseContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public Task HandleAsync([NotNull] ValidateLogoutRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (string.IsNullOrEmpty(context.PostLogoutRedirectUri))
                    {
                        return Task.CompletedTask;
                    }

                    // If an optional post_logout_redirect_uri was provided, validate it.
                    if (!Uri.TryCreate(context.PostLogoutRedirectUri, UriKind.Absolute, out Uri uri) ||
                        !uri.IsWellFormedOriginalString())
                    {
                        context.Logger.LogError("The logout request was rejected because the specified post_logout_redirect_uri " +
                                                "was not a valid absolute URL: {PostLogoutRedirectUri}.", context.PostLogoutRedirectUri);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The 'post_logout_redirect_uri' parameter must be a valid absolute URL.");

                        return Task.CompletedTask;
                    }

                    if (!string.IsNullOrEmpty(uri.Fragment))
                    {
                        context.Logger.LogError("The logout request was rejected because the 'post_logout_redirect_uri' contained " +
                                                "a URL fragment: {PostLogoutRedirectUri}.", context.PostLogoutRedirectUri);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The 'post_logout_redirect_uri' parameter must not include a fragment.");

                        return Task.CompletedTask;
                    }

                    return Task.CompletedTask;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting logout requests that use an invalid redirect_uri.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientPostLogoutRedirectUri : IOpenIddictServerHandler<ValidateLogoutRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientPostLogoutRedirectUri() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

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
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async Task HandleAsync([NotNull] ValidateLogoutRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    async Task<bool> ValidatePostLogoutRedirectUriAsync(string address)
                    {
                        var applications = await _applicationManager.FindByPostLogoutRedirectUriAsync(address);
                        if (applications.IsDefaultOrEmpty)
                        {
                            return false;
                        }

                        if (context.Options.IgnoreEndpointPermissions)
                        {
                            return true;
                        }

                        foreach (var application in applications)
                        {
                            if (await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.Logout))
                            {
                                return true;
                            }
                        }

                        return false;
                    }

                    if (!await ValidatePostLogoutRedirectUriAsync(context.PostLogoutRedirectUri))
                    {
                        context.Logger.LogError("The logout request was rejected because the specified post_logout_redirect_uri " +
                                                "was unknown: {PostLogoutRedirectUri}.", context.PostLogoutRedirectUri);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The specified 'post_logout_redirect_uri' parameter is not valid.");

                        return;
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
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public Task HandleAsync([NotNull] ApplyLogoutResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.Request == null)
                    {
                        return Task.CompletedTask;
                    }

                    // Note: at this stage, the validated redirect URI property may be null (e.g if an error
                    // is returned from the ExtractLogoutRequest/ValidateLogoutRequest events).
                    if (context.Transaction.Properties.TryGetValue(Properties.PostLogoutRedirectUri, out var property))
                    {
                        context.PostLogoutRedirectUri = (string) property;
                    }

                    return Task.CompletedTask;
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
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public Task HandleAsync([NotNull] ApplyLogoutResponseContext context)
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

                    return Task.CompletedTask;
                }
            }
        }
    }
}
