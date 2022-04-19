/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

#if !SUPPORTS_TIME_CONSTANT_COMPARISONS
using Org.BouncyCastle.Utilities;
#endif

namespace OpenIddict.Server;

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
            ApplyTokenResponse<ProcessErrorContext>.Descriptor,
            ApplyTokenResponse<ProcessRequestContext>.Descriptor,
            ApplyTokenResponse<ProcessSignInContext>.Descriptor,

            /*
             * Token request validation:
             */
            ValidateGrantType.Descriptor,
            ValidateClientIdParameter.Descriptor,
            ValidateAuthorizationCodeParameter.Descriptor,
            ValidateClientCredentialsParameters.Descriptor,
            ValidateDeviceCodeParameter.Descriptor,
            ValidateRefreshTokenParameter.Descriptor,
            ValidateResourceOwnerCredentialsParameters.Descriptor,
            ValidateProofKeyForCodeExchangeParameters.Descriptor,
            ValidateScopes.Descriptor,
            ValidateClientId.Descriptor,
            ValidateClientType.Descriptor,
            ValidateClientSecret.Descriptor,
            ValidateEndpointPermissions.Descriptor,
            ValidateGrantTypePermissions.Descriptor,
            ValidateScopePermissions.Descriptor,
            ValidateProofKeyForCodeExchangeRequirement.Descriptor,
            ValidateToken.Descriptor,
            ValidatePresenters.Descriptor,
            ValidateRedirectUri.Descriptor,
            ValidateCodeVerifier.Descriptor,
            ValidateGrantedScopes.Descriptor,

            /*
             * Token request handling:
             */
            AttachPrincipal.Descriptor,
            
            /*
             * Token response handling:
             */
            NormalizeErrorResponse.Descriptor);

        /// <summary>
        /// Contains the logic responsible for extracting token requests and invoking the corresponding event handlers.
        /// </summary>
        public class ExtractTokenRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractTokenRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireTokenRequest>()
                    .UseScopedHandler<ExtractTokenRequest>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ExtractTokenRequestContext(context.Transaction);
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
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0040));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6075), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating token requests and invoking the corresponding event handlers.
        /// </summary>
        public class ValidateTokenRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateTokenRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireTokenRequest>()
                    .UseScopedHandler<ValidateTokenRequest>()
                    .SetOrder(ExtractTokenRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ValidateTokenRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by handlers
                // that want to access the principal without triggering a new validation process.
                context.Transaction.SetProperty(typeof(ValidateTokenRequestContext).FullName!, notification);

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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6076));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling token requests and invoking the corresponding event handlers.
        /// </summary>
        public class HandleTokenRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleTokenRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireTokenRequest>()
                    .UseScopedHandler<HandleTokenRequest>()
                    .SetOrder(ValidateTokenRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new HandleTokenRequestContext(context.Transaction);
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
                        error: notification.Error ?? Errors.InvalidGrant,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                if (notification.Principal is not null)
                {
                    var @event = new ProcessSignInContext(context.Transaction)
                    {
                        Principal = notification.Principal,
                        Response = new OpenIddictResponse()
                    };

                    if (notification.Parameters.Count > 0)
                    {
                        foreach (var parameter in notification.Parameters)
                        {
                            @event.Parameters.Add(parameter.Key, parameter.Value);
                        }
                    }

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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0041));
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing sign-in responses and invoking the corresponding event handlers.
        /// </summary>
        public class ApplyTokenResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyTokenResponse(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireTokenRequest>()
                    .UseScopedHandler<ApplyTokenResponse<TContext>>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ApplyTokenResponseContext(context.Transaction);
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0042));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that specify an invalid grant type.
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reject token requests missing the mandatory grant_type parameter.
                if (string.IsNullOrEmpty(context.Request.GrantType))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6077), Parameters.GrantType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.GrantType),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                // Reject token requests that don't specify a supported grant type.
                if (!context.Options.GrantTypes.Contains(context.Request.GrantType))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6078), context.Request.GrantType);

                    context.Reject(
                        error: Errors.UnsupportedGrantType,
                        description: SR.FormatID2032(Parameters.GrantType),
                        uri: SR.FormatID8000(SR.ID2032));

                    return default;
                }

                // Reject token requests that specify scope=offline_access if the refresh token flow is not enabled.
                if (context.Request.HasScope(Scopes.OfflineAccess) &&
                   !context.Options.GrantTypes.Contains(GrantTypes.RefreshToken))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2035(Scopes.OfflineAccess),
                        uri: SR.FormatID8000(SR.ID2035));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that don't specify a client identifier.
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
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
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6077), Parameters.ClientId);

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.FormatID2029(Parameters.ClientId),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that don't
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reject grant_type=authorization_code requests missing the authorization code.
                // See https://tools.ietf.org/html/rfc6749#section-4.1.3 for more information.
                if (context.Request.IsAuthorizationCodeGrantType() && string.IsNullOrEmpty(context.Request.Code))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6077), Parameters.Code);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.Code),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that don't
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
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
                        description: SR.FormatID2057(Parameters.ClientId, Parameters.ClientSecret),
                        uri: SR.FormatID8000(SR.ID2057));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that
        /// don't specify a device code for the device code grant type.
        /// </summary>
        public class ValidateDeviceCodeParameter : IOpenIddictServerHandler<ValidateTokenRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                    .UseSingletonHandler<ValidateDeviceCodeParameter>()
                    .SetOrder(ValidateClientCredentialsParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reject grant_type=urn:ietf:params:oauth:grant-type:device_code requests missing the device code.
                // See https://tools.ietf.org/html/rfc8628#section-3.4 for more information.
                if (context.Request.IsDeviceCodeGrantType() && string.IsNullOrEmpty(context.Request.DeviceCode))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2058(Parameters.DeviceCode),
                        uri: SR.FormatID8000(SR.ID2058));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that
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
                    .SetOrder(ValidateDeviceCodeParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reject grant_type=refresh_token requests missing the refresh token.
                // See https://tools.ietf.org/html/rfc6749#section-6 for more information.
                if (context.Request.IsRefreshTokenGrantType() && string.IsNullOrEmpty(context.Request.RefreshToken))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6077), Parameters.RefreshToken);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.RefreshToken),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests
        /// that specify invalid parameters for the password grant type.
        /// </summary>
        public class ValidateResourceOwnerCredentialsParameters : IOpenIddictServerHandler<ValidateTokenRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                    .UseSingletonHandler<ValidateResourceOwnerCredentialsParameters>()
                    .SetOrder(ValidateRefreshTokenParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reject grant_type=password requests missing username or password.
                // See https://tools.ietf.org/html/rfc6749#section-4.3.2 for more information.
                if (context.Request.IsPasswordGrantType() && (string.IsNullOrEmpty(context.Request.Username) ||
                                                              string.IsNullOrEmpty(context.Request.Password)))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6079));

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2059(Parameters.Username, Parameters.Password),
                        uri: SR.FormatID8000(SR.ID2059));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that don't specify valid PKCE parameters.
        /// </summary>
        public class ValidateProofKeyForCodeExchangeParameters : IOpenIddictServerHandler<ValidateTokenRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                    .UseSingletonHandler<ValidateProofKeyForCodeExchangeParameters>()
                    .SetOrder(ValidateResourceOwnerCredentialsParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (!context.Request.IsAuthorizationCodeGrantType())
                {
                    return default;
                }

                // Optimization: the ValidateCodeVerifier event handler automatically rejects grant_type=authorization_code
                // requests missing the code_verifier parameter when a challenge was specified in the authorization request.
                // That check requires decrypting the authorization code and determining whether a code challenge was set.
                // If OpenIddict was configured to require PKCE, this can be potentially avoided by making an early check here.
                if (context.Options.RequireProofKeyForCodeExchange && string.IsNullOrEmpty(context.Request.CodeVerifier))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6033), Parameters.CodeVerifier);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.CodeVerifier),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that use unregistered scopes.
        /// Note: this handler partially works with the degraded mode but is not used when scope validation is disabled.
        /// </summary>
        public class ValidateScopes : IOpenIddictServerHandler<ValidateTokenRequestContext>
        {
            private readonly IOpenIddictScopeManager? _scopeManager;

            public ValidateScopes(IOpenIddictScopeManager? scopeManager = null)
                => _scopeManager = scopeManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                    .AddFilter<RequireScopeValidationEnabled>()
                    .UseScopedHandler<ValidateScopes>(static provider =>
                    {
                        // Note: the scope manager is only resolved if the degraded mode was not enabled to ensure
                        // invalid core configuration exceptions are not thrown even if the managers were registered.
                        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

                        return options.EnableDegradedMode ?
                            new ValidateScopes() :
                            new ValidateScopes(provider.GetService<IOpenIddictScopeManager>() ??
                                throw new InvalidOperationException(SR.GetResourceString(SR.ID0016)));
                    })
                    .SetOrder(ValidateProofKeyForCodeExchangeParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If all the specified scopes are registered in the options, avoid making a database lookup.
                var scopes = new HashSet<string>(context.Request.GetScopes(), StringComparer.Ordinal);
                scopes.ExceptWith(context.Options.Scopes);

                // Note: the remaining scopes are only checked if the degraded mode was not enabled,
                // as this requires using the scope manager, which is never used with the degraded mode,
                // even if the service was registered and resolved from the dependency injection container.
                if (scopes.Count != 0 && !context.Options.EnableDegradedMode)
                {
                    if (_scopeManager is null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));
                    }

                    await foreach (var scope in _scopeManager.FindByNamesAsync(scopes.ToImmutableArray()))
                    {
                        var name = await _scopeManager.GetNameAsync(scope);
                        if (!string.IsNullOrEmpty(name))
                        {
                            scopes.Remove(name);
                        }
                    }
                }

                // If at least one scope was not recognized, return an error.
                if (scopes.Count != 0)
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6080), scopes);

                    context.Reject(
                        error: Errors.InvalidScope,
                        description: SR.FormatID2052(Parameters.Scope),
                        uri: SR.FormatID8000(SR.ID2052));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that use an invalid client_id.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateClientId : IOpenIddictServerHandler<ValidateTokenRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientId() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientId(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateClientId>()
                    .SetOrder(ValidateScopes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                // Retrieve the application details corresponding to the requested client_id.
                // If no entity can be found, this likely indicates that the client_id is invalid.
                var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                if (application is null)
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6081), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.FormatID2052(Parameters.ClientId),
                        uri: SR.FormatID8000(SR.ID2052));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests made by applications
        /// whose client type is not compatible with the requested grant type.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateClientType : IOpenIddictServerHandler<ValidateTokenRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientType() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientType(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateClientType>()
                    .SetOrder(ValidateClientId.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public))
                {
                    // Public applications are not allowed to use the client credentials grant.
                    if (context.Request.IsClientCredentialsGrantType())
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6082), context.Request.ClientId);

                        context.Reject(
                            error: Errors.UnauthorizedClient,
                            description: SR.FormatID2043(Parameters.GrantType),
                            uri: SR.FormatID8000(SR.ID2043));

                        return;
                    }

                    // Reject token requests containing a client_secret when the client is a public application.
                    if (!string.IsNullOrEmpty(context.ClientSecret))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6083), context.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: SR.FormatID2053(Parameters.ClientSecret),
                            uri: SR.FormatID8000(SR.ID2053));

                        return;
                    }

                    return;
                }

                // Confidential and hybrid applications MUST authenticate to protect them from impersonation attacks.
                if (string.IsNullOrEmpty(context.ClientSecret))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6084), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.FormatID2054(Parameters.ClientSecret),
                        uri: SR.FormatID8000(SR.ID2054));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests specifying an invalid client secret.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateClientSecret : IOpenIddictServerHandler<ValidateTokenRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientSecret() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientSecret(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateClientSecret>()
                    .SetOrder(ValidateClientType.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // If the application is a public client, don't validate the client secret.
                if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public))
                {
                    return;
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientSecret), SR.FormatID4000(Parameters.ClientSecret));

                if (!await _applicationManager.ValidateClientSecretAsync(application, context.ClientSecret))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6085), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.GetResourceString(SR.ID2055),
                        uri: SR.FormatID8000(SR.ID2055));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests made by
        /// applications that haven't been granted the token endpoint permission.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateEndpointPermissions : IOpenIddictServerHandler<ValidateTokenRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateEndpointPermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateEndpointPermissions(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // Reject the request if the application is not allowed to use the token endpoint.
                if (!await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.Token))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6086), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2063),
                        uri: SR.FormatID8000(SR.ID2063));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests made by applications
        /// that haven't been granted the appropriate grant type permissions.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateGrantTypePermissions : IOpenIddictServerHandler<ValidateTokenRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateGrantTypePermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateGrantTypePermissions(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // Reject the request if the application is not allowed to use the specified grant type.
                if (!await _applicationManager.HasPermissionAsync(application, Permissions.Prefixes.GrantType + context.Request.GrantType))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6087), context.ClientId, context.Request.GrantType);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2064),
                        uri: SR.FormatID8000(SR.ID2064));

                    return;
                }

                // Reject the request if the offline_access scope was request and if
                // the application is not allowed to use the refresh token grant type.
                if (context.Request.HasScope(Scopes.OfflineAccess) &&
                    !await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.RefreshToken))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6088), context.ClientId, Scopes.OfflineAccess);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2065(Scopes.OfflineAccess),
                        uri: SR.FormatID8000(SR.ID2065));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests made by applications
        /// that haven't been granted the appropriate grant type permission.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateScopePermissions : IOpenIddictServerHandler<ValidateTokenRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateScopePermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateScopePermissions(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

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
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6089), context.ClientId, scope);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.GetResourceString(SR.ID2051),
                            uri: SR.FormatID8000(SR.ID2051));

                        return;
                    }
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests made by
        /// applications for which proof key for code exchange (PKCE) was enforced.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateProofKeyForCodeExchangeRequirement : IOpenIddictServerHandler<ValidateTokenRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateProofKeyForCodeExchangeRequirement() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateProofKeyForCodeExchangeRequirement(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateProofKeyForCodeExchangeRequirement>()
                    .SetOrder(ValidateScopePermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (!context.Request.IsAuthorizationCodeGrantType())
                {
                    return;
                }

                // If a code_verifier was provided, the request is always considered valid,
                // whether the proof key for code exchange requirement is enforced or not.
                if (!string.IsNullOrEmpty(context.Request.CodeVerifier))
                {
                    return;
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                if (await _applicationManager.HasRequirementAsync(application, Requirements.Features.ProofKeyForCodeExchange))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6077), Parameters.CodeVerifier);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2054(Parameters.CodeVerifier),
                        uri: SR.FormatID8000(SR.ID2054));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that don't
        /// specify a valid authorization code, device code or refresh token.
        /// </summary>
        public class ValidateToken : IOpenIddictServerHandler<ValidateTokenRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateToken(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                    .UseScopedHandler<ValidateToken>()
                    .SetOrder(ValidateProofKeyForCodeExchangeRequirement.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (!context.Request.IsAuthorizationCodeGrantType() &&
                    !context.Request.IsDeviceCodeGrantType() &&
                    !context.Request.IsRefreshTokenGrantType())
                {
                    return;
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

                // Attach the security principal extracted from the token to the validation context.
                context.Principal = context.Request.IsAuthorizationCodeGrantType() ? notification.AuthorizationCodePrincipal :
                                    context.Request.IsDeviceCodeGrantType()        ? notification.DeviceCodePrincipal :
                                    context.Request.IsRefreshTokenGrantType()      ? notification.RefreshTokenPrincipal : null;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that use an authorization code,
        /// a device code or a refresh token that was issued for a different client application.
        /// </summary>
        public class ValidatePresenters : IOpenIddictServerHandler<ValidateTokenRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                    .UseSingletonHandler<ValidatePresenters>()
                    .SetOrder(ValidateToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (!context.Request.IsAuthorizationCodeGrantType() &&
                    !context.Request.IsDeviceCodeGrantType() &&
                    !context.Request.IsRefreshTokenGrantType())
                {
                    return default;
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                var presenters = context.Principal.GetPresenters();
                if (presenters.IsDefaultOrEmpty)
                {
                    // Note: presenters may be empty during a grant_type=refresh_token request if the refresh token
                    // was issued to a public client but cannot be null for an authorization or device code grant request.
                    if (context.Request.IsAuthorizationCodeGrantType())
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0043));
                    }

                    if (context.Request.IsDeviceCodeGrantType())
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0044));
                    }

                    return default;
                }

                // If at least one presenter was associated to the authorization code/device code/refresh token,
                // reject the request if the client_id of the caller cannot be retrieved or inferred.
                if (string.IsNullOrEmpty(context.ClientId))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6090));

                    context.Reject(
                        error: Errors.InvalidGrant,
                        description: context.Request.IsAuthorizationCodeGrantType() ? SR.GetResourceString(SR.ID2066) :
                                     context.Request.IsDeviceCodeGrantType()        ? SR.GetResourceString(SR.ID2067) :
                                                                                      SR.GetResourceString(SR.ID2068),
                        uri: context.Request.IsAuthorizationCodeGrantType() ? SR.FormatID8000(SR.ID2066) :
                             context.Request.IsDeviceCodeGrantType()        ? SR.FormatID8000(SR.ID2067) :
                                                                              SR.FormatID8000(SR.ID2068));

                    return default;
                }

                // Ensure the authorization code/device code/refresh token was issued to the client making the token request.
                // Note: when using the refresh token grant, client_id is optional but MUST be validated if present.
                // See https://tools.ietf.org/html/rfc6749#section-6
                // and http://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken.
                if (!presenters.Contains(context.ClientId))
                {
                    context.Logger.LogWarning(SR.GetResourceString(SR.ID6091));

                    context.Reject(
                        error: Errors.InvalidGrant,
                        description: context.Request.IsAuthorizationCodeGrantType() ? SR.GetResourceString(SR.ID2069) :
                                     context.Request.IsDeviceCodeGrantType()        ? SR.GetResourceString(SR.ID2070) :
                                                                                      SR.GetResourceString(SR.ID2071),
                        uri: context.Request.IsAuthorizationCodeGrantType() ? SR.FormatID8000(SR.ID2069) :
                             context.Request.IsDeviceCodeGrantType()        ? SR.FormatID8000(SR.ID2070) :
                                                                              SR.FormatID8000(SR.ID2071));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that specify an invalid redirect_uri.
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (!context.Request.IsAuthorizationCodeGrantType())
                {
                    return default;
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

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
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6077), Parameters.RedirectUri);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.RedirectUri),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                if (!string.Equals(address, context.Request.RedirectUri, StringComparison.Ordinal))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6092), Parameters.RedirectUri);

                    context.Reject(
                        error: Errors.InvalidGrant,
                        description: SR.FormatID2072(Parameters.RedirectUri),
                        uri: SR.FormatID8000(SR.ID2072));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that specify an invalid code verifier.
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (!context.Request.IsAuthorizationCodeGrantType())
                {
                    return default;
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                // Note: the ValidateProofKeyForCodeExchangeRequirement handler (invoked earlier) ensures
                // a code_verifier is specified if the proof key for code exchange requirement was enforced
                // for the client application. But unlike the aforementioned handler, ValidateCodeVerifier
                // is active even if the degraded mode is enabled and ensures that a code_verifier is sent if a
                // code_challenge was stored in the authorization code when the authorization request was handled.

                var challenge = context.Principal.GetClaim(Claims.Private.CodeChallenge);
                if (string.IsNullOrEmpty(challenge))
                {
                    // Validate that the token request does not include a code_verifier parameter
                    // when code_challenge private claim was attached to the authorization code.
                    if (!string.IsNullOrEmpty(context.Request.CodeVerifier))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6093), Parameters.CodeVerifier);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2073(Parameters.CodeVerifier, Parameters.CodeChallenge),
                            uri: SR.FormatID8000(SR.ID2073));

                        return default;
                    }

                    return default;
                }

                // Get the code verifier from the token request. If it cannot be found, return an invalid_grant error.
                if (string.IsNullOrEmpty(context.Request.CodeVerifier))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6077), Parameters.CodeVerifier);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.CodeVerifier),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                // If no code challenge method was specified, default to S256.
                var method = context.Principal.GetClaim(Claims.Private.CodeChallengeMethod);
                if (string.IsNullOrEmpty(method))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0268));
                }

                // Note: when using the "plain" code challenge method, no hashing is actually performed.
                // In this case, the raw ASCII bytes of the verifier are directly compared to the challenge.
                byte[] data;
                if (string.Equals(method, CodeChallengeMethods.Plain, StringComparison.Ordinal))
                {
                    data = Encoding.ASCII.GetBytes(context.Request.CodeVerifier);
                }

                else if (string.Equals(method, CodeChallengeMethods.Sha256, StringComparison.Ordinal))
                {
                    using var algorithm = SHA256.Create();
                    data = Encoding.ASCII.GetBytes(Base64UrlEncoder.Encode(
                        algorithm.ComputeHash(Encoding.ASCII.GetBytes(context.Request.CodeVerifier))));
                }

                else
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0045));
                }

                // Compare the verifier and the code challenge: if the two don't match, return an error.
                // Note: to prevent timing attacks, a time-constant comparer is always used.
#if SUPPORTS_TIME_CONSTANT_COMPARISONS
                if (!CryptographicOperations.FixedTimeEquals(data, Encoding.ASCII.GetBytes(challenge)))
#else
                if (!Arrays.ConstantTimeAreEqual(data, Encoding.ASCII.GetBytes(challenge)))
#endif
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6092), Parameters.CodeVerifier);

                    context.Reject(
                        error: Errors.InvalidGrant,
                        description: SR.FormatID2052(Parameters.CodeVerifier),
                        uri: SR.FormatID8000(SR.ID2052));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that specify scopes that
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (!context.Request.IsAuthorizationCodeGrantType() && !context.Request.IsRefreshTokenGrantType())
                {
                    return default;
                }

                if (string.IsNullOrEmpty(context.Request.Scope))
                {
                    return default;
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                // When an explicit scope parameter has been included in the token request
                // but was missing from the initial request, the request MUST be rejected.
                // See http://tools.ietf.org/html/rfc6749#section-6 for more information.
                var scopes = new HashSet<string>(context.Principal.GetScopes(), StringComparer.Ordinal);
                if (scopes.Count == 0)
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6094), Parameters.Scope);

                    context.Reject(
                        error: Errors.InvalidGrant,
                        description: SR.FormatID2074(Parameters.Scope),
                        uri: SR.FormatID8000(SR.ID2074));

                    return default;
                }

                // When an explicit scope parameter has been included in the token request,
                // the authorization server MUST ensure that it doesn't contain scopes
                // that were not granted during the initial authorization/token request.
                // See https://tools.ietf.org/html/rfc6749#section-6 for more information.
                else if (!scopes.IsSupersetOf(context.Request.GetScopes()))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6095), Parameters.Scope);

                    context.Reject(
                        error: Errors.InvalidGrant,
                        description: SR.FormatID2052(Parameters.Scope),
                        uri: SR.FormatID8000(SR.ID2052));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the principal extracted
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (!context.Request.IsAuthorizationCodeGrantType() && !context.Request.IsRefreshTokenGrantType())
                {
                    return default;
                }

                var notification = context.Transaction.GetProperty<ValidateTokenRequestContext>(
                    typeof(ValidateTokenRequestContext).FullName!) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

                context.Principal ??= notification.Principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for converting token errors to standard invalid_grant responses.
        /// </summary>
        public class NormalizeErrorResponse : IOpenIddictServerHandler<ApplyTokenResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyTokenResponseContext>()
                    .UseSingletonHandler<NormalizeErrorResponse>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyTokenResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (string.IsNullOrEmpty(context.Error))
                {
                    return default;
                }

                // If the error indicates an invalid token caused by an invalid authorization,
                // device code or refresh token, return a standard invalid_grant.

                if (context.Request is null || !(context.Request.IsAuthorizationCodeGrantType() ||
                                                 context.Request.IsDeviceCodeGrantType() ||
                                                 context.Request.IsRefreshTokenGrantType()))
                {
                    return default;
                }

                context.Response.Error = context.Error switch
                {
                    // Keep "expired_token" errors as-is if the request is a device code token request.
                    Errors.ExpiredToken when context.Request.IsDeviceCodeGrantType() => Errors.ExpiredToken,

                    // Convert "invalid_token" errors to "invalid_grant".
                    Errors.InvalidToken => Errors.InvalidGrant,

                    _ => context.Error // Otherwise, keep the error as-is.
                };

                return default;
            }
        }
    }
}
