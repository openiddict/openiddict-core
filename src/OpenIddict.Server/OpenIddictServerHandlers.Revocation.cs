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
        public static class Revocation
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Revocation request top-level processing:
                 */
                ExtractRevocationRequest.Descriptor,
                ValidateRevocationRequest.Descriptor,
                HandleRevocationRequest.Descriptor,
                ApplyRevocationResponse<ProcessErrorContext>.Descriptor,
                ApplyRevocationResponse<ProcessRequestContext>.Descriptor,

                /*
                 * Revocation request validation:
                 */
                ValidateTokenParameter.Descriptor,
                ValidateClientIdParameter.Descriptor,
                ValidateClientId.Descriptor,
                ValidateClientType.Descriptor,
                ValidateClientSecret.Descriptor,
                ValidateEndpointPermissions.Descriptor,
                ValidateToken.Descriptor,
                ValidateTokenType.Descriptor,
                ValidateAuthorizedParty.Descriptor,

                /*
                 * Revocation request handling:
                 */
                AttachPrincipal.Descriptor,
                RevokeToken.Descriptor,

                /*
                 * Revocation response handling:
                 */
                NormalizeErrorResponse.Descriptor);

            /// <summary>
            /// Contains the logic responsible of extracting revocation requests and invoking the corresponding event handlers.
            /// </summary>
            public class ExtractRevocationRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public ExtractRevocationRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<ExtractRevocationRequest>()
                        .SetOrder(100_000)
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

                    if (context.EndpointType != OpenIddictServerEndpointType.Revocation)
                    {
                        return;
                    }

                    var notification = new ExtractRevocationRequestContext(context.Transaction);
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
                            .Append("The revocation request was not correctly extracted. To extract revocation requests, ")
                            .Append("create a class implementing 'IOpenIddictServerHandler<ExtractRevocationRequestContext>' ")
                            .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                            .ToString());
                    }

                    context.Logger.LogInformation("The revocation request was successfully extracted: {Request}.", notification.Request);
                }
            }

            /// <summary>
            /// Contains the logic responsible of validating revocation requests and invoking the corresponding event handlers.
            /// </summary>
            public class ValidateRevocationRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public ValidateRevocationRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<ValidateRevocationRequest>()
                        .SetOrder(ExtractRevocationRequest.Descriptor.Order + 1_000)
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

                    if (context.EndpointType != OpenIddictServerEndpointType.Revocation)
                    {
                        return;
                    }

                    var notification = new ValidateRevocationRequestContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

                    // Store the context object in the transaction so it can be later retrieved by handlers
                    // that want to access the principal without triggering a new validation process.
                    context.Transaction.SetProperty(typeof(ValidateRevocationRequestContext).FullName, notification);

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

                    context.Logger.LogInformation("The revocation request was successfully validated.");
                }
            }

            /// <summary>
            /// Contains the logic responsible of handling revocation requests and invoking the corresponding event handlers.
            /// </summary>
            public class HandleRevocationRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public HandleRevocationRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<HandleRevocationRequest>()
                        .SetOrder(ValidateRevocationRequest.Descriptor.Order + 1_000)
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

                    if (context.EndpointType != OpenIddictServerEndpointType.Revocation)
                    {
                        return;
                    }

                    var notification = new HandleRevocationRequestContext(context.Transaction);
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

                    context.Response = new OpenIddictResponse();
                }
            }

            /// <summary>
            /// Contains the logic responsible of processing sign-in responses and invoking the corresponding event handlers.
            /// </summary>
            public class ApplyRevocationResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
            {
                private readonly IOpenIddictServerProvider _provider;

                public ApplyRevocationResponse([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .UseScopedHandler<ApplyRevocationResponse<TContext>>()
                        .SetOrder(int.MaxValue - 100_000)
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

                    if (context.EndpointType != OpenIddictServerEndpointType.Revocation)
                    {
                        return;
                    }

                    var notification = new ApplyRevocationResponseContext(context.Transaction);
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

                    throw new InvalidOperationException(new StringBuilder()
                        .Append("The revocation response was not correctly applied. To apply revocation responses, ")
                        .Append("create a class implementing 'IOpenIddictServerHandler<ApplyRevocationResponseContext>' ")
                        .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                        .ToString());
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting revocation requests that don't specify a token.
            /// </summary>
            public class ValidateTokenParameter : IOpenIddictServerHandler<ValidateRevocationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRevocationRequestContext>()
                        .UseSingletonHandler<ValidateTokenParameter>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateRevocationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Reject revocation requests missing the mandatory token parameter.
                    if (string.IsNullOrEmpty(context.Request.Token))
                    {
                        context.Logger.LogError("The revocation request was rejected because the token was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'token' parameter is missing.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting revocation requests that don't specify a client identifier.
            /// </summary>
            public class ValidateClientIdParameter : IOpenIddictServerHandler<ValidateRevocationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRevocationRequestContext>()
                        .UseSingletonHandler<ValidateClientIdParameter>()
                        .SetOrder(ValidateTokenParameter.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateRevocationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // At this stage, reject the revocation request unless the client identification requirement was disabled.
                    if (!context.Options.AcceptAnonymousClients && string.IsNullOrEmpty(context.ClientId))
                    {
                        context.Logger.LogError("The revocation request was rejected because the mandatory 'client_id' was missing.");

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: "The mandatory 'client_id' parameter is missing.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting revocation requests that use an invalid client_id.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientId : IOpenIddictServerHandler<ValidateRevocationRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientId() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateClientId([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRevocationRequestContext>()
                        .AddFilter<RequireClientIdParameter>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .UseScopedHandler<ValidateClientId>()
                        .SetOrder(ValidateClientIdParameter.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateRevocationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Retrieve the application details corresponding to the requested client_id.
                    // If no entity can be found, this likely indicates that the client_id is invalid.
                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        context.Logger.LogError("The revocation request was rejected because the client " +
                                                "application was not found: '{ClientId}'.", context.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: "The specified 'client_id' parameter is invalid.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting revocation requests made by applications
            /// whose client type is not compatible with the presence or absence of a client secret.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientType : IOpenIddictServerHandler<ValidateRevocationRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientType() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateClientType([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRevocationRequestContext>()
                        .AddFilter<RequireClientIdParameter>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .UseScopedHandler<ValidateClientType>()
                        .SetOrder(ValidateClientId.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateRevocationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The client application details cannot be found in the database.");
                    }

                    if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public))
                    {
                        // Reject revocation requests containing a client_secret when the client is a public application.
                        if (!string.IsNullOrEmpty(context.ClientSecret))
                        {
                            context.Logger.LogError("The revocation request was rejected because the public application '{ClientId}' " +
                                                    "was not allowed to send a client secret.", context.ClientId);

                            context.Reject(
                                error: Errors.InvalidClient,
                                description: "The 'client_secret' parameter is not valid for this client application.");

                            return;
                        }

                        return;
                    }

                    // Confidential and hybrid applications MUST authenticate to protect them from impersonation attacks.
                    if (string.IsNullOrEmpty(context.ClientSecret))
                    {
                        context.Logger.LogError("The revocation request was rejected because the confidential or hybrid application " +
                                                "'{ClientId}' didn't specify a client secret.", context.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: "The 'client_secret' parameter required for this client application is missing.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting revocation requests specifying an invalid client secret.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientSecret : IOpenIddictServerHandler<ValidateRevocationRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientSecret() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateClientSecret([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRevocationRequestContext>()
                        .AddFilter<RequireClientIdParameter>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .UseScopedHandler<ValidateClientSecret>()
                        .SetOrder(ValidateClientType.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateRevocationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The client application details cannot be found in the database.");
                    }

                    // If the application is not a public client, validate the client secret.
                    if (!await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public) &&
                        !await _applicationManager.ValidateClientSecretAsync(application, context.ClientSecret))
                    {
                        context.Logger.LogError("The revocation request was rejected because the confidential or hybrid application " +
                                                "'{ClientId}' didn't specify valid client credentials.", context.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: "The specified client credentials are invalid.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting revocation requests made by
            /// applications that haven't been granted the revocation endpoint permission.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateEndpointPermissions : IOpenIddictServerHandler<ValidateRevocationRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateEndpointPermissions() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateEndpointPermissions([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRevocationRequestContext>()
                        .AddFilter<RequireClientIdParameter>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .AddFilter<RequireEndpointPermissionsEnabled>()
                        .UseScopedHandler<ValidateEndpointPermissions>()
                        .SetOrder(ValidateClientSecret.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateRevocationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The client application details cannot be found in the database.");
                    }

                    // Reject the request if the application is not allowed to use the revocation endpoint.
                    if (!await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.Revocation))
                    {
                        context.Logger.LogError("The revocation request was rejected because the application '{ClientId}' " +
                                                "was not allowed to use the revocation endpoint.", context.ClientId);

                        context.Reject(
                            error: Errors.UnauthorizedClient,
                            description: "This client application is not allowed to use the revocation endpoint.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting revocation requests that don't specify a valid token.
            /// </summary>
            public class ValidateToken : IOpenIddictServerHandler<ValidateRevocationRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public ValidateToken([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRevocationRequestContext>()
                        .UseScopedHandler<ValidateToken>()
                        .SetOrder(ValidateEndpointPermissions.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateRevocationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new ProcessAuthenticationContext(context.Transaction);
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

                    // Attach the security principal extracted from the token to the validation context.
                    context.Principal = notification.Principal;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting revocation requests that specify an unsupported token.
            /// </summary>
            public class ValidateTokenType : IOpenIddictServerHandler<ValidateRevocationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRevocationRequestContext>()
                        .UseSingletonHandler<ValidateTokenType>()
                        .SetOrder(ValidateToken.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateRevocationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (!context.Principal.HasTokenType(TokenTypeHints.AccessToken) &&
                        !context.Principal.HasTokenType(TokenTypeHints.AuthorizationCode) &&
                        !context.Principal.HasTokenType(TokenTypeHints.RefreshToken))
                    {
                        context.Logger.LogError("The revocation request was rejected because " +
                                                "the received token was of an unsupported type.");

                        context.Reject(
                            error: Errors.UnsupportedTokenType,
                            description: "This token cannot be revoked.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting revocation requests that specify a token
            /// that cannot be revoked by the client application sending the revocation requests.
            /// </summary>
            public class ValidateAuthorizedParty : IOpenIddictServerHandler<ValidateRevocationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRevocationRequestContext>()
                        // Note: when client identification is not enforced, this handler cannot validate
                        // the audiences/presenters if the client_id of the calling application is not known.
                        // In this case, the risk is quite limited as claims are never returned by this endpoint.
                        .AddFilter<RequireClientIdParameter>()
                        .UseSingletonHandler<ValidateAuthorizedParty>()
                        .SetOrder(ValidateTokenType.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateRevocationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // When the revoked token is an authorization code, the caller must be
                    // listed as a presenter (i.e the party the authorization code was issued to).
                    if (context.Principal.HasTokenType(TokenTypeHints.AuthorizationCode))
                    {
                        if (!context.Principal.HasPresenter())
                        {
                            throw new InvalidOperationException("The presenters list cannot be extracted from the authorization code.");
                        }

                        if (!context.Principal.HasPresenter(context.ClientId))
                        {
                            context.Logger.LogError("The revocation request was rejected because the " +
                                                    "authorization code was issued to a different client.");

                            context.Reject(
                                error: Errors.InvalidToken,
                                description: "The client application is not allowed to revoke the specified token.");

                            return default;
                        }

                        return default;
                    }

                    // When the revoked token is an access token, the caller must be listed either as a presenter
                    // (i.e the party the token was issued to) or as an audience (i.e a resource server/API).
                    // If the access token doesn't contain any explicit presenter/audience, the token is assumed
                    // to be not specific to any resource server/client application and the check is bypassed.
                    if (context.Principal.HasTokenType(TokenTypeHints.AccessToken) &&
                        context.Principal.HasAudience() && !context.Principal.HasAudience(context.ClientId) &&
                        context.Principal.HasPresenter() && !context.Principal.HasPresenter(context.ClientId))
                    {
                        context.Logger.LogError("The revocation request was rejected because the access token " +
                                                "was issued to a different client or for another resource server.");

                        context.Reject(
                            error: Errors.InvalidToken,
                            description: "The client application is not allowed to revoke the specified token.");

                        return default;
                    }

                    // When the revoked token is an identity token, the caller must be listed as an audience
                    // (i.e the client application the identity token was initially issued to).
                    // If the identity token doesn't contain any explicit audience, the token is
                    // assumed to be not specific to any client application and the check is bypassed.
                    if (context.Principal.HasTokenType(TokenTypeHints.IdToken) &&
                        context.Principal.HasAudience() && !context.Principal.HasAudience(context.ClientId))
                    {
                        context.Logger.LogError("The revocation request was rejected because the " +
                                                "identity token was issued to a different client.");

                        context.Reject(
                            error: Errors.InvalidToken,
                            description: "The client application is not allowed to revoke the specified token.");

                        return default;
                    }

                    // When the revoked token is a refresh token, the caller must be
                    // listed as a presenter (i.e the party the token was issued to).
                    // If the refresh token doesn't contain any explicit presenter, the token is
                    // assumed to be not specific to any client application and the check is bypassed.
                    if (context.Principal.HasTokenType(TokenTypeHints.RefreshToken) &&
                        context.Principal.HasPresenter() && !context.Principal.HasPresenter(context.ClientId))
                    {
                        context.Logger.LogError("The revocation request was rejected because the " +
                                                "refresh token was issued to a different client.");

                        context.Reject(
                            error: Errors.InvalidToken,
                            description: "The client application is not allowed to revoke the specified token.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the principal
            /// extracted from the revoked token to the event context.
            /// </summary>
            public class AttachPrincipal : IOpenIddictServerHandler<HandleRevocationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleRevocationRequestContext>()
                        .UseSingletonHandler<AttachPrincipal>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleRevocationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = context.Transaction.GetProperty<ValidateRevocationRequestContext>(
                        typeof(ValidateRevocationRequestContext).FullName) ??
                        throw new InvalidOperationException("The authentication context cannot be found.");

                    context.Principal ??= notification.Principal;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of revoking the token sent by the client application.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class RevokeToken : IOpenIddictServerHandler<HandleRevocationRequestContext>
            {
                private readonly IOpenIddictTokenManager _tokenManager;

                public RevokeToken() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public RevokeToken([NotNull] IOpenIddictTokenManager tokenManager)
                    => _tokenManager = tokenManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleRevocationRequestContext>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .UseScopedHandler<RevokeToken>()
                        .SetOrder(AttachPrincipal.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] HandleRevocationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Extract the token identifier from the authentication principal.
                    var identifier = context.Principal.GetTokenId();
                    if (string.IsNullOrEmpty(identifier))
                    {
                        context.Logger.LogError("The revocation request was rejected because the token had no internal identifier.");

                        context.Reject(
                            error: Errors.UnsupportedTokenType,
                            description: "The specified token cannot be revoked.");

                        return;
                    }

                    var token = await _tokenManager.FindByIdAsync(identifier);
                    if (token == null)
                    {
                        context.Logger.LogInformation("The token '{Identifier}' was not revoked because it couldn't be found.", identifier);

                        context.Reject(
                            error: Errors.InvalidToken,
                            description: "The specified token is invalid.");

                        return;
                    }

                    // Try to revoke the token. If an error occurs, return an error.
                    if (!await _tokenManager.TryRevokeAsync(token))
                    {
                        context.Reject(
                            error: Errors.UnsupportedTokenType,
                            description: "The specified token cannot be revoked.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of converting revocation errors to standard empty responses.
            /// </summary>
            public class NormalizeErrorResponse : IOpenIddictServerHandler<ApplyRevocationResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyRevocationResponseContext>()
                        .UseSingletonHandler<NormalizeErrorResponse>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ApplyRevocationResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (string.IsNullOrEmpty(context.Error))
                    {
                        return default;
                    }

                    // If the error indicates an invalid token, remove the error details, as required by the revocation
                    // specification. Visit https://tools.ietf.org/html/rfc7009#section-2.2 for more information.
                    // While this prevent the resource server from determining the root cause of the revocation failure,
                    // this is required to keep OpenIddict fully standard and compatible with all revocation clients.

                    if (string.Equals(context.Error, Errors.InvalidToken, StringComparison.Ordinal))
                    {
                        context.Response.Error = null;
                        context.Response.ErrorDescription = null;
                        context.Response.ErrorUri = null;
                    }

                    return default;
                }
            }
        }
    }
}
