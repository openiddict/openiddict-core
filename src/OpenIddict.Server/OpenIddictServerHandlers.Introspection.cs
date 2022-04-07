/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    public static class Introspection
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Introspection request top-level processing:
             */
            ExtractIntrospectionRequest.Descriptor,
            ValidateIntrospectionRequest.Descriptor,
            HandleIntrospectionRequest.Descriptor,
            ApplyIntrospectionResponse<ProcessErrorContext>.Descriptor,
            ApplyIntrospectionResponse<ProcessRequestContext>.Descriptor,

            /*
             * Introspection request validation:
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
             * Introspection request handling:
             */
            AttachPrincipal.Descriptor,
            AttachMetadataClaims.Descriptor,
            AttachApplicationClaims.Descriptor,

            /*
             * Introspection response handling:
             */
            NormalizeErrorResponse.Descriptor);

        /// <summary>
        /// Contains the logic responsible for extracting introspection requests and invoking the corresponding event handlers.
        /// </summary>
        public class ExtractIntrospectionRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractIntrospectionRequest(IOpenIddictServerDispatcher dispatcher!!)
                => _dispatcher = dispatcher;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireIntrospectionRequest>()
                    .UseScopedHandler<ExtractIntrospectionRequest>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context!!)
            {
                var notification = new ExtractIntrospectionRequestContext(context.Transaction);
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
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0046));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6096), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating introspection requests and invoking the corresponding event handlers.
        /// </summary>
        public class ValidateIntrospectionRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateIntrospectionRequest(IOpenIddictServerDispatcher dispatcher!!)
                => _dispatcher = dispatcher;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireIntrospectionRequest>()
                    .UseScopedHandler<ValidateIntrospectionRequest>()
                    .SetOrder(ExtractIntrospectionRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context!!)
            {
                var notification = new ValidateIntrospectionRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by handlers
                // that want to access the principal without triggering a new validation process.
                context.Transaction.SetProperty(typeof(ValidateIntrospectionRequestContext).FullName!, notification);

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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6097));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling introspection requests and invoking the corresponding event handlers.
        /// </summary>
        public class HandleIntrospectionRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleIntrospectionRequest(IOpenIddictServerDispatcher dispatcher!!)
                => _dispatcher = dispatcher;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireIntrospectionRequest>()
                    .UseScopedHandler<HandleIntrospectionRequest>()
                    .SetOrder(ValidateIntrospectionRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context!!)
            {
                var notification = new HandleIntrospectionRequestContext(context.Transaction);
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

                var response = new OpenIddictResponse
                {
                    [Claims.Active] = true,
                    [Claims.Issuer] = notification.Issuer?.AbsoluteUri,
                    [Claims.Username] = notification.Username,
                    [Claims.Subject] = notification.Subject,
                    [Claims.Scope] = string.Join(" ", notification.Scopes),
                    [Claims.JwtId] = notification.TokenId,
                    [Claims.TokenType] = notification.TokenType,
                    [Claims.TokenUsage] = notification.TokenUsage,
                    [Claims.ClientId] = notification.ClientId
                };

                if (notification.IssuedAt is not null)
                {
                    response[Claims.IssuedAt] = EpochTime.GetIntDate(notification.IssuedAt.Value.UtcDateTime);
                }

                if (notification.NotBefore is not null)
                {
                    response[Claims.NotBefore] = EpochTime.GetIntDate(notification.NotBefore.Value.UtcDateTime);
                }

                if (notification.ExpiresAt is not null)
                {
                    response[Claims.ExpiresAt] = EpochTime.GetIntDate(notification.ExpiresAt.Value.UtcDateTime);
                }

                switch (notification.Audiences.Count)
                {
                    case 0: break;

                    case 1:
                        response[Claims.Audience] = notification.Audiences.ElementAt(0);
                        break;

                    default:
                        response[Claims.Audience] = notification.Audiences.ToArray();
                        break;
                }

                foreach (var claim in notification.Claims)
                {
                    response.SetParameter(claim.Key, claim.Value);
                }

                context.Transaction.Response = response;
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing sign-in responses and invoking the corresponding event handlers.
        /// </summary>
        public class ApplyIntrospectionResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyIntrospectionResponse(IOpenIddictServerDispatcher dispatcher!!)
                => _dispatcher = dispatcher;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireIntrospectionRequest>()
                    .UseScopedHandler<ApplyIntrospectionResponse<TContext>>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context!!)
            {
                var notification = new ApplyIntrospectionResponseContext(context.Transaction);
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0047));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting introspection requests that don't specify a token.
        /// </summary>
        public class ValidateTokenParameter : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateIntrospectionRequestContext>()
                    .UseSingletonHandler<ValidateTokenParameter>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateIntrospectionRequestContext context!!)
            {
                // Reject introspection requests missing the mandatory token parameter.
                if (string.IsNullOrEmpty(context.Request.Token))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6098), Parameters.Token);

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
        /// Contains the logic responsible for rejecting introspection requests that don't specify a client identifier.
        /// </summary>
        public class ValidateClientIdParameter : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateIntrospectionRequestContext>()
                    .UseSingletonHandler<ValidateClientIdParameter>()
                    .SetOrder(ValidateTokenParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateIntrospectionRequestContext context!!)
            {
                // At this stage, reject the introspection request unless the client identification requirement was disabled.
                if (!context.Options.AcceptAnonymousClients && string.IsNullOrEmpty(context.ClientId))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6098), Parameters.ClientId);

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
        /// Contains the logic responsible for rejecting introspection requests that use an invalid client_id.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateClientId : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientId() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientId(IOpenIddictApplicationManager applicationManager!!)
                => _applicationManager = applicationManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateIntrospectionRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateClientId>()
                    .SetOrder(ValidateClientIdParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateIntrospectionRequestContext context!!)
            {
                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                // Retrieve the application details corresponding to the requested client_id.
                // If no entity can be found, this likely indicates that the client_id is invalid.
                var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                if (application is null)
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6099), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.FormatID2052(Parameters.ClientId),
                        uri: SR.FormatID8000(SR.ID2052));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting introspection requests made by applications
        /// whose client type is not compatible with the presence or absence of a client secret.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateClientType : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientType() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientType(IOpenIddictApplicationManager applicationManager!!)
                => _applicationManager = applicationManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateIntrospectionRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateClientType>()
                    .SetOrder(ValidateClientId.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateIntrospectionRequestContext context!!)
            {
                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                if (application is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));
                }

                if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public))
                {
                    // Reject introspection requests containing a client_secret when the client is a public application.
                    if (!string.IsNullOrEmpty(context.ClientSecret))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6100), context.ClientId);

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
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6101), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.FormatID2054(Parameters.ClientSecret),
                        uri: SR.FormatID8000(SR.ID2054));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting introspection requests specifying an invalid client secret.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateClientSecret : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientSecret() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientSecret(IOpenIddictApplicationManager applicationManager!!)
                => _applicationManager = applicationManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateIntrospectionRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateClientSecret>()
                    .SetOrder(ValidateClientType.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateIntrospectionRequestContext context!!)
            {
                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                if (application is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));
                }

                // If the application is a public client, don't validate the client secret.
                if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public))
                {
                    return;
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientSecret), SR.FormatID4000(Parameters.ClientSecret));

                if (!await _applicationManager.ValidateClientSecretAsync(application, context.ClientSecret))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6102), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.GetResourceString(SR.ID2055),
                        uri: SR.FormatID8000(SR.ID2055));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting introspection requests made by
        /// applications that haven't been granted the introspection endpoint permission.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateEndpointPermissions : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateEndpointPermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateEndpointPermissions(IOpenIddictApplicationManager applicationManager!!)
                => _applicationManager = applicationManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateIntrospectionRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireEndpointPermissionsEnabled>()
                    .UseScopedHandler<ValidateEndpointPermissions>()
                    .SetOrder(ValidateClientSecret.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateIntrospectionRequestContext context!!)
            {
                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                if (application is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));
                }

                // Reject the request if the application is not allowed to use the introspection endpoint.
                if (!await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.Introspection))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6103), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2075),
                        uri: SR.FormatID8000(SR.ID2075));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting introspection requests that don't specify a valid token.
        /// </summary>
        public class ValidateToken : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateToken(IOpenIddictServerDispatcher dispatcher!!)
                => _dispatcher = dispatcher;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateIntrospectionRequestContext>()
                    .UseScopedHandler<ValidateToken>()
                    .SetOrder(ValidateEndpointPermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateIntrospectionRequestContext context!!)
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
        /// Contains the logic responsible for rejecting introspection requests that specify an unsupported token.
        /// </summary>
        public class ValidateTokenType : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateIntrospectionRequestContext>()
                    .UseSingletonHandler<ValidateTokenType>()
                    .SetOrder(ValidateToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateIntrospectionRequestContext context!!)
            {
                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                if (!context.Principal.HasTokenType(TokenTypeHints.AccessToken) &&
                    !context.Principal.HasTokenType(TokenTypeHints.RefreshToken))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6104));

                    context.Reject(
                        error: Errors.UnsupportedTokenType,
                        description: SR.GetResourceString(SR.ID2076),
                        uri: SR.FormatID8000(SR.ID2076));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting introspection requests that specify a token
        /// that cannot be introspected by the client application sending the introspection requests.
        /// </summary>
        public class ValidateAuthorizedParty : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateIntrospectionRequestContext>()
                    // Note: when client identification is not enforced, this handler cannot validate
                    // the audiences/presenters if the client_id of the calling application is not known.
                    // In this case, the returned claims are limited by AttachApplicationClaims to limit exposure.
                    .AddFilter<RequireClientIdParameter>()
                    .UseSingletonHandler<ValidateAuthorizedParty>()
                    .SetOrder(ValidateTokenType.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateIntrospectionRequestContext context!!)
            {
                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));
                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                // When the introspected token is an access token, the caller must be listed either as a presenter
                // (i.e the party the token was issued to) or as an audience (i.e a resource server/API).
                // If the access token doesn't contain any explicit presenter/audience, the token is assumed
                // to be not specific to any resource server/client application and the check is bypassed.
                if (context.Principal.HasTokenType(TokenTypeHints.AccessToken) &&
                    context.Principal.HasClaim(Claims.Private.Audience) && !context.Principal.HasAudience(context.ClientId) &&
                    context.Principal.HasClaim(Claims.Private.Presenter) && !context.Principal.HasPresenter(context.ClientId))
                {
                    context.Logger.LogWarning(SR.GetResourceString(SR.ID6106));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2077),
                        uri: SR.FormatID8000(SR.ID2077));

                    return default;
                }

                // When the introspected token is a refresh token, the caller must be
                // listed as a presenter (i.e the party the token was issued to).
                // If the refresh token doesn't contain any explicit presenter, the token is
                // assumed to be not specific to any client application and the check is bypassed.
                if (context.Principal.HasTokenType(TokenTypeHints.RefreshToken) &&
                    context.Principal.HasClaim(Claims.Private.Presenter) && !context.Principal.HasPresenter(context.ClientId))
                {
                    context.Logger.LogWarning(SR.GetResourceString(SR.ID6108));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2077),
                        uri: SR.FormatID8000(SR.ID2077));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the principal
        /// extracted from the introspected token to the event context.
        /// </summary>
        public class AttachPrincipal : IOpenIddictServerHandler<HandleIntrospectionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleIntrospectionRequestContext>()
                    .UseSingletonHandler<AttachPrincipal>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleIntrospectionRequestContext context!!)
            {
                var notification = context.Transaction.GetProperty<ValidateIntrospectionRequestContext>(
                    typeof(ValidateIntrospectionRequestContext).FullName!) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

                Debug.Assert(notification.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                context.Principal ??= notification.Principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the metadata claims extracted from the token the event context.
        /// </summary>
        public class AttachMetadataClaims : IOpenIddictServerHandler<HandleIntrospectionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleIntrospectionRequestContext>()
                    .UseSingletonHandler<AttachMetadataClaims>()
                    .SetOrder(AttachPrincipal.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleIntrospectionRequestContext context!!)
            {
                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                context.TokenId = context.Principal.GetClaim(Claims.JwtId);
                context.TokenUsage = context.Principal.GetTokenType();
                context.Subject = context.Principal.GetClaim(Claims.Subject);

                context.IssuedAt = context.NotBefore = context.Principal.GetCreationDate();
                context.ExpiresAt = context.Principal.GetExpirationDate();

                // Infer the audiences/client_id from the claims stored in the security principal.
                context.Audiences.UnionWith(context.Principal.GetAudiences());
                context.ClientId = context.Principal.GetClaim(Claims.ClientId) ??
                                   context.Principal.GetPresenters().FirstOrDefault();

                // Note: only set "token_type" when the received token is an access token.
                // See https://tools.ietf.org/html/rfc7662#section-2.2
                // and https://tools.ietf.org/html/rfc6749#section-5.1 for more information.
                if (context.Principal.HasTokenType(TokenTypeHints.AccessToken))
                {
                    context.TokenType = TokenTypes.Bearer;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the application-specific claims extracted from the token the event context.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class AttachApplicationClaims : IOpenIddictServerHandler<HandleIntrospectionRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public AttachApplicationClaims() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public AttachApplicationClaims(IOpenIddictApplicationManager applicationManager!!)
                => _applicationManager = applicationManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleIntrospectionRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<AttachApplicationClaims>()
                    .SetOrder(AttachMetadataClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(HandleIntrospectionRequestContext context!!)
            {
                Debug.Assert(!string.IsNullOrEmpty(context.Request.ClientId), SR.FormatID4000(Parameters.ClientId));
                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                // Don't return application-specific claims if the token is not an access token.
                if (!context.Principal.HasTokenType(TokenTypeHints.AccessToken))
                {
                    return;
                }

                // Only specified audiences (that were explicitly defined as allowed resources) can access
                // the sensitive application-specific claims contained in the introspected access token.
                if (!context.Principal.HasAudience(context.Request.ClientId))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6105), context.Request.ClientId);

                    return;
                }

                var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                if (application is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));
                }

                // Public clients are not allowed to access sensitive claims as authentication cannot be enforced.
                if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6107), context.Request.ClientId);

                    return;
                }

                context.Username = context.Principal.Identity.Name;
                context.Scopes.UnionWith(context.Principal.GetScopes());

                foreach (var group in context.Principal.Claims.GroupBy(claim => claim.Type))
                {
                    // Exclude standard claims, that are already handled via strongly-typed properties.
                    // Make sure to always update this list when adding new built-in claim properties.
                    var type = group.Key;
                    if (type is Claims.Audience or Claims.ExpiresAt or Claims.IssuedAt or
                                Claims.Issuer   or Claims.NotBefore or Claims.Scope or
                                Claims.Subject  or Claims.TokenType or Claims.TokenUsage)
                    {
                        continue;
                    }

                    // Exclude OpenIddict-specific metadata claims, that are always considered private.
                    if (type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var claims = group.ToList();
                    context.Claims[type] = claims.Count switch
                    {
                        // When there's only one claim with the same type, directly
                        // convert the claim using the specified claim value type.
                        1 => ConvertToParameter(claims[0]),

                        // When multiple claims share the same type, retrieve the underlying
                        // JSON values and add everything to a new unique JSON array.
                        _ => DeserializeElement(SerializeClaims(claims))
                    };
                }

                static OpenIddictParameter ConvertToParameter(Claim claim) => claim.ValueType switch
                {
                    ClaimValueTypes.Boolean => bool.Parse(claim.Value),

                    ClaimValueTypes.Integer or ClaimValueTypes.Integer32
                        => int.Parse(claim.Value, CultureInfo.InvariantCulture),

                    ClaimValueTypes.Integer64 => long.Parse(claim.Value, CultureInfo.InvariantCulture),

                    JsonClaimValueTypes.Json or JsonClaimValueTypes.JsonArray => DeserializeElement(claim.Value),

                    _ => new OpenIddictParameter(claim.Value)
                };

                static JsonElement DeserializeElement(string value)
                {
                    using var document = JsonDocument.Parse(value);
                    return document.RootElement.Clone();
                }

                static string SerializeClaims(IReadOnlyList<Claim> claims)
                {
                    using var stream = new MemoryStream();
                    using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
                    {
                        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                        Indented = false
                    });

                    writer.WriteStartArray();

                    for (var index = 0; index < claims.Count; index++)
                    {
                        var claim = claims[index];

                        switch (claim.ValueType)
                        {
                            case ClaimValueTypes.Boolean:
                                writer.WriteBooleanValue(bool.Parse(claim.Value));
                                break;

                            case ClaimValueTypes.Integer:
                            case ClaimValueTypes.Integer32:
                                writer.WriteNumberValue(int.Parse(claim.Value, CultureInfo.InvariantCulture));
                                break;

                            case ClaimValueTypes.Integer64:
                                writer.WriteNumberValue(long.Parse(claim.Value, CultureInfo.InvariantCulture));
                                break;

                            case JsonClaimValueTypes.Json:
                            case JsonClaimValueTypes.JsonArray:
                                using (var document = JsonDocument.Parse(claim.Value))
                                {
                                    document.WriteTo(writer);
                                }
                                break;

                            default:
                                writer.WriteStringValue(claim.Value);
                                break;
                        }
                    }

                    writer.WriteEndArray();
                    writer.Flush();

                    return Encoding.UTF8.GetString(stream.ToArray());
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for converting introspection errors to standard active: false responses.
        /// </summary>
        public class NormalizeErrorResponse : IOpenIddictServerHandler<ApplyIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyIntrospectionResponseContext>()
                    .UseSingletonHandler<NormalizeErrorResponse>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyIntrospectionResponseContext context!!)
            {
                if (string.IsNullOrEmpty(context.Error))
                {
                    return default;
                }

                // If the error indicates an invalid token, remove the error details and only return active: false,
                // as required by the introspection specification: https://tools.ietf.org/html/rfc7662#section-2.2.
                // While this prevent the resource server from determining the root cause of the introspection failure,
                // this is required to keep OpenIddict fully standard and compatible with all introspection clients.

                if (string.Equals(context.Error, Errors.InvalidToken, StringComparison.Ordinal))
                {
                    context.Response.Error = null;
                    context.Response.ErrorDescription = null;
                    context.Response.ErrorUri = null;

                    context.Response[Claims.Active] = false;
                }

                return default;
            }
        }
    }
}
