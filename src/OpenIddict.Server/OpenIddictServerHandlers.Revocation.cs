/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Server;

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
        /// Contains the logic responsible for extracting revocation requests and invoking the corresponding event handlers.
        /// </summary>
        public class ExtractRevocationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractRevocationRequest(IOpenIddictServerDispatcher dispatcher!!)
                => _dispatcher = dispatcher;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireRevocationRequest>()
                    .UseScopedHandler<ExtractRevocationRequest>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context!!)
            {
                var notification = new ExtractRevocationRequestContext(context.Transaction);
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
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0048));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6109), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating revocation requests and invoking the corresponding event handlers.
        /// </summary>
        public class ValidateRevocationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateRevocationRequest(IOpenIddictServerDispatcher dispatcher!!)
                => _dispatcher = dispatcher;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireRevocationRequest>()
                    .UseScopedHandler<ValidateRevocationRequest>()
                    .SetOrder(ExtractRevocationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context!!)
            {
                var notification = new ValidateRevocationRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by handlers
                // that want to access the principal without triggering a new validation process.
                context.Transaction.SetProperty(typeof(ValidateRevocationRequestContext).FullName!, notification);

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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6110));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling revocation requests and invoking the corresponding event handlers.
        /// </summary>
        public class HandleRevocationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleRevocationRequest(IOpenIddictServerDispatcher dispatcher!!)
                => _dispatcher = dispatcher;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireRevocationRequest>()
                    .UseScopedHandler<HandleRevocationRequest>()
                    .SetOrder(ValidateRevocationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context!!)
            {
                var notification = new HandleRevocationRequestContext(context.Transaction);
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

                context.Transaction.Response = new OpenIddictResponse();
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing sign-in responses and invoking the corresponding event handlers.
        /// </summary>
        public class ApplyRevocationResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyRevocationResponse(IOpenIddictServerDispatcher dispatcher!!)
                => _dispatcher = dispatcher;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireRevocationRequest>()
                    .UseScopedHandler<ApplyRevocationResponse<TContext>>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context!!)
            {
                var notification = new ApplyRevocationResponseContext(context.Transaction);
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0049));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting revocation requests that don't specify a token.
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateRevocationRequestContext context!!)
            {
                // Reject revocation requests missing the mandatory token parameter.
                if (string.IsNullOrEmpty(context.Request.Token))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6111), Parameters.Token);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.Token),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting revocation requests that don't specify a client identifier.
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateRevocationRequestContext context!!)
            {
                // At this stage, reject the revocation request unless the client identification requirement was disabled.
                if (!context.Options.AcceptAnonymousClients && string.IsNullOrEmpty(context.ClientId))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6111), Parameters.ClientId);

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
        /// Contains the logic responsible for rejecting revocation requests that use an invalid client_id.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateClientId : IOpenIddictServerHandler<ValidateRevocationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientId() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientId(IOpenIddictApplicationManager applicationManager!!)
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateRevocationRequestContext context!!)
            {
                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                // Retrieve the application details corresponding to the requested client_id.
                // If no entity can be found, this likely indicates that the client_id is invalid.
                var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                if (application is null)
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6112), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.FormatID2052(Parameters.ClientId),
                        uri: SR.FormatID8000(SR.ID2052));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting revocation requests made by applications
        /// whose client type is not compatible with the presence or absence of a client secret.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateClientType : IOpenIddictServerHandler<ValidateRevocationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientType() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientType(IOpenIddictApplicationManager applicationManager!!)
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateRevocationRequestContext context!!)
            {
                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public))
                {
                    // Reject revocation requests containing a client_secret when the client is a public application.
                    if (!string.IsNullOrEmpty(context.ClientSecret))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6113), context.ClientId);

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
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6114), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.FormatID2054(Parameters.ClientSecret),
                        uri: SR.FormatID8000(SR.ID2054));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting revocation requests specifying an invalid client secret.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateClientSecret : IOpenIddictServerHandler<ValidateRevocationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientSecret() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientSecret(IOpenIddictApplicationManager applicationManager!!)
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateRevocationRequestContext context!!)
            {
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
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6115), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.GetResourceString(SR.ID2055),
                        uri: SR.FormatID8000(SR.ID2055));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting revocation requests made by
        /// applications that haven't been granted the revocation endpoint permission.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateEndpointPermissions : IOpenIddictServerHandler<ValidateRevocationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateEndpointPermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateEndpointPermissions(IOpenIddictApplicationManager applicationManager!!)
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateRevocationRequestContext context!!)
            {
                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // Reject the request if the application is not allowed to use the revocation endpoint.
                if (!await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.Revocation))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6116), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2078),
                        uri: SR.FormatID8000(SR.ID2078));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting revocation requests that don't specify a valid token.
        /// </summary>
        public class ValidateToken : IOpenIddictServerHandler<ValidateRevocationRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateToken(IOpenIddictServerDispatcher dispatcher!!)
                => _dispatcher = dispatcher;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRevocationRequestContext>()
                    .UseScopedHandler<ValidateToken>()
                    .SetOrder(ValidateEndpointPermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateRevocationRequestContext context!!)
            {
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
                context.Principal = notification.GenericTokenPrincipal;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting revocation requests that specify an unsupported token.
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateRevocationRequestContext context!!)
            {
                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                if (!context.Principal.HasTokenType(TokenTypeHints.AccessToken) &&
                    !context.Principal.HasTokenType(TokenTypeHints.RefreshToken))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6117));

                    context.Reject(
                        error: Errors.UnsupportedTokenType,
                        description: SR.GetResourceString(SR.ID2079),
                        uri: SR.FormatID8000(SR.ID2079));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting revocation requests that specify a token
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateRevocationRequestContext context!!)
            {
                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));
                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                // When the revoked token is an access token, the caller must be listed either as a presenter
                // (i.e the party the token was issued to) or as an audience (i.e a resource server/API).
                // If the access token doesn't contain any explicit presenter/audience, the token is assumed
                // to be not specific to any resource server/client application and the check is bypassed.
                if (context.Principal.HasTokenType(TokenTypeHints.AccessToken) &&
                    context.Principal.HasClaim(Claims.Private.Audience) && !context.Principal.HasAudience(context.ClientId) &&
                    context.Principal.HasClaim(Claims.Private.Presenter) && !context.Principal.HasPresenter(context.ClientId))
                {
                    context.Logger.LogWarning(SR.GetResourceString(SR.ID6119));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2080),
                        uri: SR.FormatID8000(SR.ID2080));

                    return default;
                }

                // When the revoked token is a refresh token, the caller must be
                // listed as a presenter (i.e the party the token was issued to).
                // If the refresh token doesn't contain any explicit presenter, the token is
                // assumed to be not specific to any client application and the check is bypassed.
                if (context.Principal.HasTokenType(TokenTypeHints.RefreshToken) &&
                    context.Principal.HasClaim(Claims.Private.Presenter) && !context.Principal.HasPresenter(context.ClientId))
                {
                    context.Logger.LogWarning(SR.GetResourceString(SR.ID6121));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2080),
                        uri: SR.FormatID8000(SR.ID2080));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the principal
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleRevocationRequestContext context!!)
            {
                var notification = context.Transaction.GetProperty<ValidateRevocationRequestContext>(
                    typeof(ValidateRevocationRequestContext).FullName!) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

                Debug.Assert(notification.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                context.Principal ??= notification.Principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for revoking the token sent by the client application.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RevokeToken : IOpenIddictServerHandler<HandleRevocationRequestContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RevokeToken() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public RevokeToken(IOpenIddictTokenManager tokenManager!!)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleRevocationRequestContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<RevokeToken>()
                    .SetOrder(AttachPrincipal.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(HandleRevocationRequestContext context!!)
            {
                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                // Extract the token identifier from the authentication principal.
                var identifier = context.Principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6122));

                    context.Reject(
                        error: Errors.UnsupportedTokenType,
                        description: SR.GetResourceString(SR.ID2079),
                        uri: SR.FormatID8000(SR.ID2079));

                    return;
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token is null)
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6123), identifier);

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2004),
                        uri: SR.FormatID8000(SR.ID2004));

                    return;
                }

                // Try to revoke the token. If an error occurs, return an error.
                if (!await _tokenManager.TryRevokeAsync(token))
                {
                    context.Reject(
                        error: Errors.UnsupportedTokenType,
                        description: SR.GetResourceString(SR.ID2079),
                        uri: SR.FormatID8000(SR.ID2079));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for converting revocation errors to standard empty responses.
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyRevocationResponseContext context!!)
            {
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
