/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using Properties = OpenIddict.Server.OpenIddictServerConstants.Properties;

namespace OpenIddict.Server
{
    public static partial class OpenIddictServerHandlers
    {
        public static class Exchange
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Token request top-level processing:
                 */
                ExtractTokenRequest.Descriptor,
                ValidateTokenRequest.Descriptor,
                HandleTokenRequest.Descriptor,
                ApplyTokenResponse<ProcessChallengeContext>.Descriptor,
                ApplyTokenResponse<ProcessErrorResponseContext>.Descriptor,
                ApplyTokenResponse<ProcessRequestContext>.Descriptor,
                ApplyTokenResponse<ProcessSigninContext>.Descriptor,

                /*
                 * Token request validation:
                 */
                ValidateGrantType.Descriptor,
                ValidateClientIdParameter.Descriptor,
                ValidateAuthorizationCodeParameter.Descriptor,
                ValidateClientCredentialsParameters.Descriptor,
                ValidateRefreshTokenParameter.Descriptor,
                ValidatePasswordParameters.Descriptor,
                ValidateScopes.Descriptor,
                ValidateClientId.Descriptor,
                ValidateClientType.Descriptor,
                ValidateClientSecret.Descriptor,
                ValidateEndpointPermissions.Descriptor,
                ValidateGrantTypePermissions.Descriptor,
                ValidateScopePermissions.Descriptor,
                ValidateAuthorizationCode.Descriptor,
                ValidateRefreshToken.Descriptor,
                ValidatePresenters.Descriptor,
                ValidateRedirectUri.Descriptor,
                ValidateCodeVerifier.Descriptor,
                ValidateGrantedScopes.Descriptor,
                ValidateAuthorization.Descriptor,

                /*
                 * Token request handling:
                 */
                AttachPrincipal.Descriptor);

            /// <summary>
            /// Contains the logic responsible of extracting token requests and invoking the corresponding event handlers.
            /// </summary>
            public class ExtractTokenRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public ExtractTokenRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<ExtractTokenRequest>()
                        .SetOrder(int.MinValue + 100_000)
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

                    if (context.EndpointType != OpenIddictServerEndpointType.Token)
                    {
                        return;
                    }

                    var notification = new ExtractTokenRequestContext(context.Transaction);
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
                            .Append("The token request was not correctly extracted. To extract token requests, ")
                            .Append("create a class implementing 'IOpenIddictServerHandler<ExtractTokenRequestContext>' ")
                            .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                            .ToString());
                    }

                    context.Logger.LogInformation("The token request was successfully extracted: {Request}.", notification.Request);
                }
            }

            /// <summary>
            /// Contains the logic responsible of validating token requests and invoking the corresponding event handlers.
            /// </summary>
            public class ValidateTokenRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public ValidateTokenRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<ValidateTokenRequest>()
                        .SetOrder(ExtractTokenRequest.Descriptor.Order + 1_000)
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

                    if (context.EndpointType != OpenIddictServerEndpointType.Token)
                    {
                        return;
                    }

                    var notification = new ValidateTokenRequestContext(context.Transaction);
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

                    // Store the security principal extracted from the authorization code/refresh token as an environment property.
                    context.Transaction.Properties[Properties.AmbientPrincipal] = notification.Principal;

                    context.Logger.LogInformation("The token request was successfully validated.");
                }
            }

            /// <summary>
            /// Contains the logic responsible of handling token requests and invoking the corresponding event handlers.
            /// </summary>
            public class HandleTokenRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public HandleTokenRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<HandleTokenRequest>()
                        .SetOrder(ValidateTokenRequest.Descriptor.Order + 1_000)
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

                    if (context.EndpointType != OpenIddictServerEndpointType.Token)
                    {
                        return;
                    }

                    var notification = new HandleTokenRequestContext(context.Transaction);
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

                    if (notification.Principal != null)
                    {
                        var @event = new ProcessSigninContext(context.Transaction)
                        {
                            Principal = notification.Principal,
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
                        .Append("The token request was not handled. To handle token requests, ")
                        .Append("create a class implementing 'IOpenIddictServerHandler<HandleTokenRequestContext>' ")
                        .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                        .Append("Alternatively, enable the pass-through mode to handle them at a later stage.")
                        .ToString());
                }
            }

            /// <summary>
            /// Contains the logic responsible of processing sign-in responses and invoking the corresponding event handlers.
            /// </summary>
            public class ApplyTokenResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
            {
                private readonly IOpenIddictServerProvider _provider;

                public ApplyTokenResponse([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .UseScopedHandler<ApplyTokenResponse<TContext>>()
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

                    if (context.EndpointType != OpenIddictServerEndpointType.Token)
                    {
                        return;
                    }

                    var notification = new ApplyTokenResponseContext(context.Transaction);
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
            /// Contains the logic responsible of rejecting token requests that specify an invalid grant type.
            /// </summary>
            public class ValidateGrantType : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .UseSingletonHandler<ValidateGrantType>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Reject token requests missing the mandatory grant_type parameter.
                    if (string.IsNullOrEmpty(context.Request.GrantType))
                    {
                        context.Logger.LogError("The token request was rejected because the grant type was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'grant_type' parameter is missing.");

                        return default;
                    }

                    // Reject token requests that don't specify a supported grant type.
                    if (!context.Options.GrantTypes.Contains(context.Request.GrantType))
                    {
                        context.Logger.LogError("The token request was rejected because the '{GrantType}' " +
                                                "grant type is not supported.", context.Request.GrantType);

                        context.Reject(
                            error: Errors.UnsupportedGrantType,
                            description: "The specified 'grant_type' parameter is not supported.");

                        return default;
                    }

                    // Reject token requests that specify scope=offline_access if the refresh token flow is not enabled.
                    if (context.Request.HasScope(Scopes.OfflineAccess) &&
                       !context.Options.GrantTypes.Contains(GrantTypes.RefreshToken))
                    {
                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The 'offline_access' scope is not allowed.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests that don't specify a client identifier.
            /// </summary>
            public class ValidateClientIdParameter : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .UseSingletonHandler<ValidateClientIdParameter>()
                        .SetOrder(ValidateGrantType.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (!string.IsNullOrEmpty(context.ClientId))
                    {
                        return default;
                    }

                    // At this stage, reject the token request unless the client identification requirement was disabled.
                    // Independently of this setting, also reject grant_type=authorization_code requests that don't specify
                    // a client_id, as the client identifier MUST be sent by the client application in the request body
                    // if it cannot be inferred from the client authentication method (e.g the username when using basic).
                    // See https://tools.ietf.org/html/rfc6749#section-4.1.3 for more information.
                    if (!context.Options.AcceptAnonymousClients || context.Request.IsAuthorizationCodeGrantType())
                    {
                        context.Logger.LogError("The token request was rejected because the mandatory 'client_id' was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'client_id' parameter is missing.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests that don't
            /// specify an authorization code for the authorization code grant type.
            /// </summary>
            public class ValidateAuthorizationCodeParameter : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .UseSingletonHandler<ValidateAuthorizationCodeParameter>()
                        .SetOrder(ValidateClientIdParameter.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Reject grant_type=authorization_code requests missing the authorization code.
                    // See https://tools.ietf.org/html/rfc6749#section-4.1.3 for more information.
                    if (context.Request.IsAuthorizationCodeGrantType() && string.IsNullOrEmpty(context.Request.Code))
                    {
                        context.Logger.LogError("The token request was rejected because the authorization code was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'code' parameter is missing.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests that don't
            /// specify client credentials for the client credentials grant type.
            /// </summary>
            public class ValidateClientCredentialsParameters : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .UseSingletonHandler<ValidateClientCredentialsParameters>()
                        .SetOrder(ValidateAuthorizationCodeParameter.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Reject grant_type=client_credentials requests missing the client credentials.
                    // See https://tools.ietf.org/html/rfc6749#section-4.4.1 for more information.
                    if (context.Request.IsClientCredentialsGrantType() && (string.IsNullOrEmpty(context.Request.ClientId) ||
                                                                           string.IsNullOrEmpty(context.Request.ClientSecret)))
                    {
                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The 'client_id' and 'client_secret' parameters are " +
                                         "required when using the client credentials grant.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests that
            /// specify invalid parameters for the refresh token grant type.
            /// </summary>
            public class ValidateRefreshTokenParameter : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .UseSingletonHandler<ValidateRefreshTokenParameter>()
                        .SetOrder(ValidateClientCredentialsParameters.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Reject grant_type=refresh_token requests missing the refresh token.
                    // See https://tools.ietf.org/html/rfc6749#section-6 for more information.
                    if (context.Request.IsRefreshTokenGrantType() && string.IsNullOrEmpty(context.Request.RefreshToken))
                    {
                        context.Logger.LogError("The token request was rejected because the refresh token was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'refresh_token' parameter is missing.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests
            /// that specify invalid parameters for the password grant type.
            /// </summary>
            public class ValidatePasswordParameters : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .UseSingletonHandler<ValidatePasswordParameters>()
                        .SetOrder(ValidateRefreshTokenParameter.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Reject grant_type=password requests missing username or password.
                    // See https://tools.ietf.org/html/rfc6749#section-4.3.2 for more information.
                    if (context.Request.IsPasswordGrantType() && (string.IsNullOrEmpty(context.Request.Username) ||
                                                                  string.IsNullOrEmpty(context.Request.Password)))
                    {
                        context.Logger.LogError("The token request was rejected because the resource owner credentials were missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'username' and/or 'password' parameters are missing.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests that use unregistered scopes.
            /// Note: this handler is not used when the degraded mode is enabled or when scope validation is disabled.
            /// </summary>
            public class ValidateScopes : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                private readonly IOpenIddictScopeManager _scopeManager;

                public ValidateScopes() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateScopes([NotNull] IOpenIddictScopeManager scopeManager)
                    => _scopeManager = scopeManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .AddFilter<RequireScopeValidationEnabled>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .UseScopedHandler<ValidateScopes>()
                        .SetOrder(ValidatePasswordParameters.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // If all the specified scopes are registered in the options, avoid making a database lookup.
                    var scopes = context.Request.GetScopes().Except(context.Options.Scopes);
                    if (scopes.Count != 0)
                    {
                        await foreach (var scope in _scopeManager.FindByNamesAsync(scopes.ToImmutableArray()))
                        {
                            scopes = scopes.Remove(await _scopeManager.GetNameAsync(scope));
                        }
                    }

                    // If at least one scope was not recognized, return an error.
                    if (scopes.Count != 0)
                    {
                        context.Logger.LogError("The token request was rejected because " +
                                                "invalid scopes were specified: {Scopes}.", scopes);

                        context.Reject(
                            error: Errors.InvalidScope,
                            description: "The specified 'scope' parameter is not valid.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests that use an invalid client_id.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientId : IOpenIddictServerHandler<ValidateTokenRequestContext>
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
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .AddFilter<RequireClientIdParameter>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .UseScopedHandler<ValidateClientId>()
                        .SetOrder(ValidateScopes.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
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
                        context.Logger.LogError("The token request was rejected because the client " +
                                                "application was not found: '{ClientId}'.", context.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: "The specified 'client_id' parameter is invalid.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests made by applications
            /// whose client type is not compatible with the requested grant type.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientType : IOpenIddictServerHandler<ValidateTokenRequestContext>
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
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
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
                public async ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
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

                    if (await _applicationManager.IsPublicAsync(application))
                    {
                        // Public applications are not allowed to use the client credentials grant.
                        if (context.Request.IsClientCredentialsGrantType())
                        {
                            context.Logger.LogError("The token request was rejected because the public client application '{ClientId}' " +
                                                    "was not allowed to use the client credentials grant.", context.Request.ClientId);

                            context.Reject(
                                error: Errors.UnauthorizedClient,
                                description: "The specified 'grant_type' parameter is not valid for this client application.");

                            return;
                        }

                        // Reject token requests containing a client_secret when the client is a public application.
                        if (!string.IsNullOrEmpty(context.ClientSecret))
                        {
                            context.Logger.LogError("The token request was rejected because the public application '{ClientId}' " +
                                                    "was not allowed to send a client secret.", context.ClientId);

                            context.Reject(
                                error: Errors.InvalidRequest,
                                description: "The 'client_secret' parameter is not valid for this client application.");

                            return;
                        }

                        return;
                    }

                    // Confidential and hybrid applications MUST authenticate to protect them from impersonation attacks.
                    if (string.IsNullOrEmpty(context.ClientSecret))
                    {
                        context.Logger.LogError("The token request was rejected because the confidential or hybrid application " +
                                                "'{ClientId}' didn't specify a client secret.", context.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: "The 'client_secret' parameter required for this client application is missing.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests specifying an invalid client secret.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientSecret : IOpenIddictServerHandler<ValidateTokenRequestContext>
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
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
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
                public async ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
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
                    if (!await _applicationManager.IsPublicAsync(application) &&
                        !await _applicationManager.ValidateClientSecretAsync(application, context.ClientSecret))
                    {
                        context.Logger.LogError("The token request was rejected because the confidential or hybrid application " +
                                                "'{ClientId}' didn't specify valid client credentials.", context.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: "The specified client credentials are invalid.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests made by
            /// applications that haven't been granted the token endpoint permission.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateEndpointPermissions : IOpenIddictServerHandler<ValidateTokenRequestContext>
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
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
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
                public async ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
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

                    // Reject the request if the application is not allowed to use the token endpoint.
                    if (!await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.Token))
                    {
                        context.Logger.LogError("The token request was rejected because the application '{ClientId}' " +
                                                "was not allowed to use the token endpoint.", context.ClientId);

                        context.Reject(
                            error: Errors.UnauthorizedClient,
                            description: "This client application is not allowed to use the token endpoint.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests made by applications
            /// that haven't been granted the appropriate grant type permissions.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateGrantTypePermissions : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateGrantTypePermissions() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateGrantTypePermissions([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .AddFilter<RequireClientIdParameter>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .AddFilter<RequireGrantTypePermissionsEnabled>()
                        .UseScopedHandler<ValidateGrantTypePermissions>()
                        .SetOrder(ValidateEndpointPermissions.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
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

                    // Reject the request if the application is not allowed to use the specified grant type.
                    if (!await _applicationManager.HasPermissionAsync(application, Permissions.Prefixes.GrantType + context.Request.GrantType))
                    {
                        context.Logger.LogError("The token request was rejected because the application '{ClientId}' was not allowed to " +
                                                "use the specified grant type: {GrantType}.", context.ClientId, context.Request.GrantType);

                        context.Reject(
                            error: Errors.UnauthorizedClient,
                            description: "This client application is not allowed to use the specified grant type.");

                        return;
                    }

                    // Reject the request if the offline_access scope was request and if
                    // the application is not allowed to use the refresh token grant type.
                    if (context.Request.HasScope(Scopes.OfflineAccess) &&
                        !await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.RefreshToken))
                    {
                        context.Logger.LogError("The token request was rejected because the application '{ClientId}' " +
                                                "was not allowed to request the 'offline_access' scope.", context.ClientId);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The client application is not allowed to use the 'offline_access' scope.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests made by applications
            /// that haven't been granted the appropriate grant type permission.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateScopePermissions : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateScopePermissions() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateScopePermissions([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .AddFilter<RequireClientIdParameter>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .AddFilter<RequireScopePermissionsEnabled>()
                        .UseScopedHandler<ValidateScopePermissions>()
                        .SetOrder(ValidateGrantTypePermissions.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
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

                    foreach (var scope in context.Request.GetScopes())
                    {
                        // Avoid validating the "openid" and "offline_access" scopes as they represent protocol scopes.
                        if (string.Equals(scope, Scopes.OfflineAccess, StringComparison.Ordinal) ||
                            string.Equals(scope, Scopes.OpenId, StringComparison.Ordinal))
                        {
                            continue;
                        }

                        // Reject the request if the application is not allowed to use the iterated scope.
                        if (!await _applicationManager.HasPermissionAsync(application, Permissions.Prefixes.Scope + scope))
                        {
                            context.Logger.LogError("The token request was rejected because the application '{ClientId}' " +
                                                    "was not allowed to use the scope {Scope}.", context.ClientId, scope);

                            context.Reject(
                                error: Errors.InvalidRequest,
                                description: "This client application is not allowed to use the specified scope.");

                            return;
                        }
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests that specify an invalid authorization code.
            /// </summary>
            public class ValidateAuthorizationCode : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public ValidateAuthorizationCode([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .UseScopedHandler<ValidateAuthorizationCode>()
                        // This handler is deliberately registered with a high order to ensure it runs
                        // after custom handlers registered with the default order and prevent the token
                        // endpoint from disclosing whether an authorization code or refresh token is
                        // valid before the caller's identity can first be fully verified.
                        .SetOrder(100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (!context.Request.IsAuthorizationCodeGrantType())
                    {
                        return;
                    }

                    var notification = new DeserializeAuthorizationCodeContext(context.Transaction)
                    {
                        Token = context.Request.Code
                    };

                    await _provider.DispatchAsync(notification);

                    if (notification.Principal == null)
                    {
                        context.Logger.LogError("The token request was rejected because the authorization code was invalid.");

                        context.Reject(
                            error: Errors.InvalidGrant,
                            description: "The specified authorization code is invalid.");

                        return;
                    }

                    var date = notification.Principal.GetExpirationDate();
                    if (date.HasValue && date.Value < DateTimeOffset.UtcNow)
                    {
                        context.Logger.LogError("The token request was rejected because the authorization code was expired.");

                        context.Reject(
                            error: Errors.InvalidGrant,
                            description: "The specified authorization code is no longer valid.");

                        return;
                    }

                    // Attach the principal extracted from the authorization code to the parent event context.
                    context.Principal = notification.Principal;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests that specify an invalid refresh token.
            /// </summary>
            public class ValidateRefreshToken : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public ValidateRefreshToken([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .UseScopedHandler<ValidateRefreshToken>()
                        .SetOrder(ValidateAuthorizationCode.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (!context.Request.IsRefreshTokenGrantType())
                    {
                        return;
                    }

                    var notification = new DeserializeRefreshTokenContext(context.Transaction)
                    {
                        Token = context.Request.RefreshToken
                    };

                    await _provider.DispatchAsync(notification);

                    if (notification.Principal == null)
                    {
                        context.Logger.LogError("The token request was rejected because the refresh token was invalid.");

                        context.Reject(
                            error: Errors.InvalidGrant,
                            description: "The specified refresh token is invalid.");

                        return;
                    }

                    var date = notification.Principal.GetExpirationDate();
                    if (date.HasValue && date.Value < DateTimeOffset.UtcNow)
                    {
                        context.Logger.LogError("The token request was rejected because the refresh token was expired.");

                        context.Reject(
                            error: Errors.InvalidGrant,
                            description: "The specified refresh token is no longer valid.");

                        return;
                    }

                    // Attach the principal extracted from the refresh token to the parent event context.
                    context.Principal = notification.Principal;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests that use an authorization code
            /// or a refresh token that was issued for a different client application.
            /// </summary>
            public class ValidatePresenters : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .UseSingletonHandler<ValidatePresenters>()
                        .SetOrder(ValidateRefreshToken.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (!context.Request.IsAuthorizationCodeGrantType() && !context.Request.IsRefreshTokenGrantType())
                    {
                        return default;
                    }

                    var presenters = context.Principal.GetPresenters();
                    if (presenters.Count == 0)
                    {
                        // Note: presenters may be empty during a grant_type=refresh_token request if the refresh token
                        // was issued to a public client but cannot be null for an authorization code grant request.
                        if (context.Request.IsAuthorizationCodeGrantType())
                        {
                            throw new InvalidOperationException("The presenters list cannot be extracted from the authorization code.");
                        }

                        return default;
                    }

                    // If at least one presenter was associated to the authorization code/refresh token,
                    // reject the request if the client_id of the caller cannot be retrieved or inferred.
                    if (string.IsNullOrEmpty(context.ClientId))
                    {
                        context.Logger.LogError("The token request was rejected because the client identifier of the application " +
                                                "was not available and could not be compared to the presenters list stored " +
                                                "in the authorization code or the refresh token.");

                        context.Reject(
                            error: Errors.InvalidGrant,
                            description: context.Request.IsAuthorizationCodeGrantType() ?
                                "The specified authorization code cannot be used without specifying a client identifier." :
                                "The specified refresh token cannot be used without specifying a client identifier.");

                        return default;
                    }

                    // Ensure the authorization code/refresh token was issued to the client application making the token request.
                    // Note: when using the refresh token grant, client_id is optional but MUST be validated if present.
                    // See https://tools.ietf.org/html/rfc6749#section-6
                    // and http://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken.
                    if (!presenters.Contains(context.ClientId))
                    {
                        context.Logger.LogError("The token request was rejected because the authorization code " +
                                                "or the refresh token was issued to a different client application.");

                        context.Reject(
                            error: Errors.InvalidGrant,
                            description: context.Request.IsAuthorizationCodeGrantType() ?
                                "The specified authorization code cannot be used by this client application." :
                                "The specified refresh token cannot be used by this client application.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests that specify an invalid redirect_uri.
            /// </summary>
            public class ValidateRedirectUri : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .UseSingletonHandler<ValidateRedirectUri>()
                        .SetOrder(ValidatePresenters.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (!context.Request.IsAuthorizationCodeGrantType())
                    {
                        return default;
                    }

                    // Validate the redirect_uri sent by the client application as part of this token request.
                    // Note: for pure OAuth 2.0 requests, redirect_uri is only mandatory if the authorization request
                    // contained an explicit redirect_uri. OpenID Connect requests MUST include a redirect_uri
                    // but the specifications allow proceeding the token request without returning an error
                    // if the authorization request didn't contain an explicit redirect_uri.
                    // See https://tools.ietf.org/html/rfc6749#section-4.1.3
                    // and http://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation.
                    var address = context.Principal.GetClaim(Claims.Private.RedirectUri);
                    if (string.IsNullOrEmpty(address))
                    {
                        return default;
                    }

                    if (string.IsNullOrEmpty(context.Request.RedirectUri))
                    {
                        context.Logger.LogError("The token request was rejected because the mandatory 'redirect_uri' " +
                                                "parameter was missing from the grant_type=authorization_code request.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'redirect_uri' parameter is missing.");

                        return default;
                    }

                    if (!string.Equals(address, context.Request.RedirectUri, StringComparison.Ordinal))
                    {
                        context.Logger.LogError("The token request was rejected because the 'redirect_uri' " +
                                                "parameter didn't correspond to the expected value.");

                        context.Reject(
                            error: Errors.InvalidGrant,
                            description: "The specified 'redirect_uri' parameter doesn't match the client " +
                                         "redirection endpoint the authorization code was initially sent to.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests that specify an invalid code verifier.
            /// </summary>
            public class ValidateCodeVerifier : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .UseSingletonHandler<ValidateCodeVerifier>()
                        .SetOrder(ValidateRedirectUri.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (!context.Request.IsAuthorizationCodeGrantType())
                    {
                        return default;
                    }

                    // If a code challenge was initially sent in the authorization request and associated with the
                    // code, validate the code verifier to ensure the token request is sent by a legit caller.
                    var challenge = context.Principal.GetClaim(Claims.Private.CodeChallenge);
                    if (string.IsNullOrEmpty(challenge))
                    {
                        return default;
                    }

                    // Get the code verifier from the token request.
                    // If it cannot be found, return an invalid_grant error.
                    if (string.IsNullOrEmpty(context.Request.CodeVerifier))
                    {
                        context.Logger.LogError("The token request was rejected because the required 'code_verifier' " +
                                                "parameter was missing from the grant_type=authorization_code request.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'code_verifier' parameter is missing.");

                        return default;
                    }

                    // If no code challenge method was specified, default to S256.
                    var method = context.Principal.GetClaim(Claims.Private.CodeChallengeMethod);
                    if (string.IsNullOrEmpty(method))
                    {
                        method = CodeChallengeMethods.Sha256;
                    }

                    // Note: when using the "plain" code challenge method, no hashing is actually performed.
                    // In this case, the raw ASCII bytes of the verifier are directly compared to the challenge.
                    ReadOnlySpan<byte> data;
                    if (string.Equals(method, CodeChallengeMethods.Plain, StringComparison.Ordinal))
                    {
                        data = Encoding.ASCII.GetBytes(context.Request.CodeVerifier);
                    }

                    else if (string.Equals(method, CodeChallengeMethods.Sha256, StringComparison.Ordinal))
                    {
                        using var algorithm = SHA256.Create();
                        data = algorithm.ComputeHash(Encoding.ASCII.GetBytes(context.Request.CodeVerifier));
                    }

                    else
                    {
                        context.Logger.LogError("The token request was rejected because the 'code_challenge_method' was invalid.");

                        context.Reject(
                            error: Errors.InvalidGrant,
                            description: "The specified 'code_challenge_method' is invalid.");

                        return default;
                    }

                    // Compare the verifier and the code challenge: if the two don't match, return an error.
                    // Note: to prevent timing attacks, a time-constant comparer is always used.
                    if (!FixedTimeEquals(data, Base64UrlEncoder.DecodeBytes(challenge)))
                    {
                        context.Logger.LogError("The token request was rejected because the 'code_verifier' was invalid.");

                        context.Reject(
                            error: Errors.InvalidGrant,
                            description: "The specified 'code_verifier' parameter is invalid.");

                        return default;
                    }

                    return default;
                }

                [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
                private static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
                {
#if SUPPORTS_TIME_CONSTANT_COMPARISONS
                    return CryptographicOperations.FixedTimeEquals(left, right);
#else
                    // Note: these null checks can be theoretically considered as early checks
                    // (which would defeat the purpose of a time-constant comparison method),
                    // but the expected string length is the only information an attacker
                    // could get at this stage, which is not critical where this method is used.

                    if (left.Length != right.Length)
                    {
                        return false;
                    }

                    var result = true;

                    for (var index = 0; index < left.Length; index++)
                    {
                        result &= left[index] == right[index];
                    }

                    return result;
#endif
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests that specify scopes that
            /// were not initially granted by the resource owner during the authorization request.
            /// </summary>
            public class ValidateGrantedScopes : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .UseSingletonHandler<ValidateGrantedScopes>()
                        .SetOrder(ValidateCodeVerifier.Descriptor.Order + 1_000)
                        .Build();

                public ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (!context.Request.IsAuthorizationCodeGrantType() || string.IsNullOrEmpty(context.Request.Scope))
                    {
                        return default;
                    }

                    // When an explicit scope parameter has been included in the token request
                    // but was missing from the initial request, the request MUST be rejected.
                    // See http://tools.ietf.org/html/rfc6749#section-6 for more information.
                    var scopes = context.Principal.GetScopes();
                    if (scopes.Count == 0)
                    {
                        context.Logger.LogError("The token request was rejected because the 'scope' parameter was not allowed.");

                        context.Reject(
                            error: Errors.InvalidGrant,
                            description: "The 'scope' parameter is not valid in this context.");

                        return default;
                    }

                    // When an explicit scope parameter has been included in the token request,
                    // the authorization server MUST ensure that it doesn't contain scopes
                    // that were not allowed during the initial authorization/token request.
                    // See https://tools.ietf.org/html/rfc6749#section-6 for more information.
                    else if (!scopes.IsSupersetOf(context.Request.GetScopes()))
                    {
                        context.Logger.LogError("The token request was rejected because the 'scope' parameter was not valid.");

                        context.Reject(
                            error: Errors.InvalidGrant,
                            description: "The specified 'scope' parameter is invalid.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting token requests that use an authorization code
            /// or refresh token whose associated authorization is no longer valid (e.g was revoked).
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateAuthorization : IOpenIddictServerHandler<ValidateTokenRequestContext>
            {
                private readonly IOpenIddictAuthorizationManager _authorizationManager;

                public ValidateAuthorization() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateAuthorization([NotNull] IOpenIddictAuthorizationManager authorizationManager)
                    => _authorizationManager = authorizationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .AddFilter<RequireAuthorizationStorageEnabled>()
                        .UseScopedHandler<ValidateAuthorization>()
                        .SetOrder(ValidateGrantedScopes.Descriptor.Order + 1_000)
                        .Build();

                public async ValueTask HandleAsync([NotNull] ValidateTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var identifier = context.Principal.GetInternalAuthorizationId();
                    if (string.IsNullOrEmpty(identifier))
                    {
                        return;
                    }

                    var authorization = await _authorizationManager.FindByIdAsync(identifier);
                    if (authorization == null || !await _authorizationManager.IsValidAsync(authorization))
                    {
                        context.Logger.LogError("The token '{Identifier}' was rejected because the associated " +
                                                "authorization was no longer valid.", context.Principal.GetPublicTokenId());

                        context.Reject(
                            error: Errors.InvalidGrant,
                            description: context.Request.IsAuthorizationCodeGrantType() ?
                                "The authorization associated with the authorization code is no longer valid." :
                                "The authorization associated with the refresh token is no longer valid.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the principal extracted
            /// from the authorization code/refresh token to the event context.
            /// </summary>
            public class AttachPrincipal : IOpenIddictServerHandler<HandleTokenRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleTokenRequestContext>()
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
                public ValueTask HandleAsync([NotNull] HandleTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (!context.Request.IsAuthorizationCodeGrantType() && !context.Request.IsRefreshTokenGrantType())
                    {
                        return default;
                    }

                    if (context.Transaction.Properties.TryGetValue(Properties.AmbientPrincipal, out var principal))
                    {
                        context.Principal ??= (ClaimsPrincipal) principal;
                    }

                    return default;
                }
            }
        }
    }
}
