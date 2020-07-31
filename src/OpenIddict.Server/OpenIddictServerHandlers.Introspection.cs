/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server
{
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
            /// Contains the logic responsible of extracting introspection requests and invoking the corresponding event handlers.
            /// </summary>
            public class ExtractIntrospectionRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ExtractIntrospectionRequest(IOpenIddictServerDispatcher dispatcher)
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
                public async ValueTask HandleAsync(ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

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

                    if (notification.Request == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1045));
                    }

                    context.Logger.LogInformation(SR.GetResourceString(SR.ID7096), notification.Request);
                }
            }

            /// <summary>
            /// Contains the logic responsible of validating introspection requests and invoking the corresponding event handlers.
            /// </summary>
            public class ValidateIntrospectionRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ValidateIntrospectionRequest(IOpenIddictServerDispatcher dispatcher)
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
                public async ValueTask HandleAsync(ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

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

                    context.Logger.LogInformation(SR.GetResourceString(SR.ID7097));
                }
            }

            /// <summary>
            /// Contains the logic responsible of handling introspection requests and invoking the corresponding event handlers.
            /// </summary>
            public class HandleIntrospectionRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public HandleIntrospectionRequest(IOpenIddictServerDispatcher dispatcher)
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
                public async ValueTask HandleAsync(ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

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

                    if (notification.IssuedAt != null)
                    {
                        response[Claims.IssuedAt] = EpochTime.GetIntDate(notification.IssuedAt.Value.UtcDateTime);
                    }

                    if (notification.NotBefore != null)
                    {
                        response[Claims.NotBefore] = EpochTime.GetIntDate(notification.NotBefore.Value.UtcDateTime);
                    }

                    if (notification.ExpiresAt != null)
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
            /// Contains the logic responsible of processing sign-in responses and invoking the corresponding event handlers.
            /// </summary>
            public class ApplyIntrospectionResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ApplyIntrospectionResponse(IOpenIddictServerDispatcher dispatcher)
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
                public async ValueTask HandleAsync(TContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

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

                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1046));
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting introspection requests that don't specify a token.
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
                public ValueTask HandleAsync(ValidateIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Reject introspection requests missing the mandatory token parameter.
                    if (string.IsNullOrEmpty(context.Request.Token))
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID7098), Parameters.Token);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: context.Localizer[SR.ID3029, Parameters.Token]);

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting introspection requests that don't specify a client identifier.
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
                public ValueTask HandleAsync(ValidateIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // At this stage, reject the introspection request unless the client identification requirement was disabled.
                    if (!context.Options.AcceptAnonymousClients && string.IsNullOrEmpty(context.ClientId))
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID7098), Parameters.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: context.Localizer[SR.ID3029, Parameters.ClientId]);

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting introspection requests that use an invalid client_id.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientId : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientId() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

                public ValidateClientId(IOpenIddictApplicationManager applicationManager)
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
                public async ValueTask HandleAsync(ValidateIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID5000(Parameters.ClientId));

                    // Retrieve the application details corresponding to the requested client_id.
                    // If no entity can be found, this likely indicates that the client_id is invalid.
                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID7099), context.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: context.Localizer[SR.ID3052, Parameters.ClientId]);

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting introspection requests made by applications
            /// whose client type is not compatible with the presence or absence of a client secret.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientType : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientType() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

                public ValidateClientType(IOpenIddictApplicationManager applicationManager)
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
                public async ValueTask HandleAsync(ValidateIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID5000(Parameters.ClientId));

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1031));
                    }

                    if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public))
                    {
                        // Reject introspection requests containing a client_secret when the client is a public application.
                        if (!string.IsNullOrEmpty(context.ClientSecret))
                        {
                            context.Logger.LogError(SR.GetResourceString(SR.ID7100), context.ClientId);

                            context.Reject(
                                error: Errors.InvalidClient,
                                description: context.Localizer[SR.ID3053, Parameters.ClientSecret]);

                            return;
                        }

                        return;
                    }

                    // Confidential and hybrid applications MUST authenticate to protect them from impersonation attacks.
                    if (string.IsNullOrEmpty(context.ClientSecret))
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID7101), context.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: context.Localizer[SR.ID3054, Parameters.ClientSecret]);

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting introspection requests specifying an invalid client secret.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientSecret : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientSecret() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

                public ValidateClientSecret(IOpenIddictApplicationManager applicationManager)
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
                public async ValueTask HandleAsync(ValidateIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID5000(Parameters.ClientId));

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1031));
                    }

                    // If the application is a public client, don't validate the client secret.
                    if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public))
                    {
                        return;
                    }

                    Debug.Assert(!string.IsNullOrEmpty(context.ClientSecret), SR.FormatID5000(Parameters.ClientSecret));

                    if (!await _applicationManager.ValidateClientSecretAsync(application, context.ClientSecret))
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID7102), context.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: context.Localizer[SR.ID3055]);

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting introspection requests made by
            /// applications that haven't been granted the introspection endpoint permission.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateEndpointPermissions : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateEndpointPermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

                public ValidateEndpointPermissions(IOpenIddictApplicationManager applicationManager)
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
                public async ValueTask HandleAsync(ValidateIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID5000(Parameters.ClientId));

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1031));
                    }

                    // Reject the request if the application is not allowed to use the introspection endpoint.
                    if (!await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.Introspection))
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID7103), context.ClientId);

                        context.Reject(
                            error: Errors.UnauthorizedClient,
                            description: context.Localizer[SR.ID3075]);

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting introspection requests that don't specify a valid token.
            /// </summary>
            public class ValidateToken : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ValidateToken(IOpenIddictServerDispatcher dispatcher)
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
                public async ValueTask HandleAsync(ValidateIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new ProcessAuthenticationContext(context.Transaction);
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

                    // Attach the security principal extracted from the token to the validation context.
                    context.Principal = notification.Principal;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting introspection requests that specify an unsupported token.
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
                public ValueTask HandleAsync(ValidateIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(context.Principal != null, SR.GetResourceString(SR.ID5006));

                    if (!context.Principal.HasTokenType(TokenTypeHints.AccessToken) &&
                        !context.Principal.HasTokenType(TokenTypeHints.AuthorizationCode) &&
                        !context.Principal.HasTokenType(TokenTypeHints.IdToken) &&
                        !context.Principal.HasTokenType(TokenTypeHints.RefreshToken))
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID7104));

                        context.Reject(
                            error: Errors.UnsupportedTokenType,
                            description: context.Localizer[SR.ID3076]);

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting introspection requests that specify a token
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
                public ValueTask HandleAsync(ValidateIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID5000(Parameters.ClientId));
                    Debug.Assert(context.Principal != null, SR.GetResourceString(SR.ID5006));

                    // When the introspected token is an authorization code, the caller must be
                    // listed as a presenter (i.e the party the authorization code was issued to).
                    if (context.Principal.HasTokenType(TokenTypeHints.AuthorizationCode))
                    {
                        if (!context.Principal.HasPresenter())
                        {
                            throw new InvalidOperationException(SR.GetResourceString(SR.ID1042));
                        }

                        if (!context.Principal.HasPresenter(context.ClientId))
                        {
                            context.Logger.LogError(SR.GetResourceString(SR.ID7105));

                            context.Reject(
                                error: Errors.InvalidToken,
                                description: context.Localizer[SR.ID3077]);

                            return default;
                        }

                        return default;
                    }

                    // When the introspected token is an access token, the caller must be listed either as a presenter
                    // (i.e the party the token was issued to) or as an audience (i.e a resource server/API).
                    // If the access token doesn't contain any explicit presenter/audience, the token is assumed
                    // to be not specific to any resource server/client application and the check is bypassed.
                    if (context.Principal.HasTokenType(TokenTypeHints.AccessToken) &&
                        context.Principal.HasAudience() && !context.Principal.HasAudience(context.ClientId) &&
                        context.Principal.HasPresenter() && !context.Principal.HasPresenter(context.ClientId))
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID7106));

                        context.Reject(
                            error: Errors.InvalidToken,
                            description: context.Localizer[SR.ID3077]);

                        return default;
                    }

                    // When the introspected token is an identity token, the caller must be listed as an audience
                    // (i.e the client application the identity token was initially issued to).
                    // If the identity token doesn't contain any explicit audience, the token is
                    // assumed to be not specific to any client application and the check is bypassed.
                    if (context.Principal.HasTokenType(TokenTypeHints.IdToken) &&
                        context.Principal.HasAudience() && !context.Principal.HasAudience(context.ClientId))
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID7107));

                        context.Reject(
                            error: Errors.InvalidToken,
                            description: context.Localizer[SR.ID3077]);

                        return default;
                    }

                    // When the introspected token is a refresh token, the caller must be
                    // listed as a presenter (i.e the party the token was issued to).
                    // If the refresh token doesn't contain any explicit presenter, the token is
                    // assumed to be not specific to any client application and the check is bypassed.
                    if (context.Principal.HasTokenType(TokenTypeHints.RefreshToken) &&
                        context.Principal.HasPresenter() && !context.Principal.HasPresenter(context.ClientId))
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID7108));

                        context.Reject(
                            error: Errors.InvalidToken,
                            description: context.Localizer[SR.ID3077]);

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the principal
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
                public ValueTask HandleAsync(HandleIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = context.Transaction.GetProperty<ValidateIntrospectionRequestContext>(
                        typeof(ValidateIntrospectionRequestContext).FullName!) ??
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1006));

                    context.Principal ??= notification.Principal;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the metadata claims extracted from the token the event context.
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
                public ValueTask HandleAsync(HandleIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(context.Principal != null, SR.GetResourceString(SR.ID5006));

                    context.TokenId = context.Principal.GetClaim(Claims.JwtId);
                    context.TokenUsage = context.Principal.GetTokenType();
                    context.Subject = context.Principal.GetClaim(Claims.Subject);

                    context.IssuedAt = context.NotBefore = context.Principal.GetCreationDate();
                    context.ExpiresAt = context.Principal.GetExpirationDate();

                    // Infer the audiences/client_id claims from the properties stored in the security principal.
                    // Note: the client_id claim must be a unique string so multiple presenters cannot be returned.
                    // To work around this limitation, only the first one is returned if multiple values are listed.
                    context.Audiences.UnionWith(context.Principal.GetAudiences());
                    context.ClientId = context.Principal.GetPresenters().FirstOrDefault();

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
            /// Contains the logic responsible of attaching the application-specific claims extracted from the token the event context.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class AttachApplicationClaims : IOpenIddictServerHandler<HandleIntrospectionRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public AttachApplicationClaims() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

                public AttachApplicationClaims(IOpenIddictApplicationManager applicationManager)
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
                public async ValueTask HandleAsync(HandleIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(!string.IsNullOrEmpty(context.Request.ClientId), SR.FormatID5000(Parameters.ClientId));
                    Debug.Assert(context.Principal != null, SR.GetResourceString(SR.ID5006));

                    // Don't return application-specific claims if the token is not an access or identity token.
                    if (!context.Principal.HasTokenType(TokenTypeHints.AccessToken) && !context.Principal.HasTokenType(TokenTypeHints.IdToken))
                    {
                        return;
                    }

                    // Only the specified audience (i.e the resource server for an access token
                    // and the client application for an identity token) can access the sensitive
                    // application-specific claims contained in the introspected access/identity token.
                    if (!context.Principal.HasAudience(context.Request.ClientId))
                    {
                        return;
                    }

                    var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1031));
                    }

                    // Public clients are not allowed to access sensitive claims as authentication cannot be enforced.
                    if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public))
                    {
                        return;
                    }

                    context.Username = context.Principal.Identity.Name;
                    context.Scopes.UnionWith(context.Principal.GetScopes());

                    foreach (var grouping in context.Principal.Claims.GroupBy(claim => claim.Type))
                    {
                        // Exclude standard claims, that are already handled via strongly-typed properties.
                        // Make sure to always update this list when adding new built-in claim properties.
                        var type = grouping.Key;
                        switch (type)
                        {
                            case Claims.Audience:
                            case Claims.ExpiresAt:
                            case Claims.IssuedAt:
                            case Claims.Issuer:
                            case Claims.NotBefore:
                            case Claims.Scope:
                            case Claims.Subject:
                            case Claims.TokenType:
                            case Claims.TokenUsage:
                                continue;
                        }

                        // Exclude OpenIddict-specific metadata claims, that are always considered private.
                        if (type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        var claims = grouping.ToArray();
                        context.Claims[type] = claims.Length switch
                        {
                            // When there's only one claim with the same type, directly
                            // convert the claim using the specified claim value type.
                            1 => ConvertToParameter(claims[0]),

                            // When multiple claims share the same type, retrieve the underlying
                            // JSON values and add everything to a new unique JSON array.
                            _ => DeserializeElement(JsonSerializer.Serialize(
                                claims.Select(claim => ConvertToParameter(claim).Value), new JsonSerializerOptions
                                {
                                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                                    WriteIndented = false
                                }))
                        };
                    }

                    static OpenIddictParameter ConvertToParameter(Claim claim) => claim.ValueType switch
                    {
                        ClaimValueTypes.Boolean => bool.Parse(claim.Value),

                        ClaimValueTypes.Integer   => int.Parse(claim.Value, CultureInfo.InvariantCulture),
                        ClaimValueTypes.Integer32 => int.Parse(claim.Value, CultureInfo.InvariantCulture),
                        ClaimValueTypes.Integer64 => long.Parse(claim.Value, CultureInfo.InvariantCulture),

                        JsonClaimValueTypes.Json      => DeserializeElement(claim.Value),
                        JsonClaimValueTypes.JsonArray => DeserializeElement(claim.Value),

                        _ => new OpenIddictParameter(claim.Value)
                    };

                    static JsonElement DeserializeElement(string value)
                    {
                        using var document = JsonDocument.Parse(value);
                        return document.RootElement.Clone();
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of converting introspection errors to standard active: false responses.
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
                public ValueTask HandleAsync(ApplyIntrospectionResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

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
}
