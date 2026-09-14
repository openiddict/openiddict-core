/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    public static class Backchannel
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Backchannel authentication request top-level processing:
             */
            ExtractBackchannelAuthenticationRequest.Descriptor,
            ValidateBackchannelAuthenticationRequest.Descriptor,
            HandleBackchannelAuthenticationRequest.Descriptor,
            ApplyBackchannelAuthenticationResponse<ProcessChallengeContext>.Descriptor,
            ApplyBackchannelAuthenticationResponse<ProcessErrorContext>.Descriptor,
            ApplyBackchannelAuthenticationResponse<ProcessRequestContext>.Descriptor,
            ApplyBackchannelAuthenticationResponse<ProcessSignInContext>.Descriptor,

            /*
             * Backchannel authentication request validation:
             */
            ValidateRequestParameter.Descriptor,
            ValidateScopeParameter.Descriptor,
            ValidateHintParameters.Descriptor,
            ValidateRequestedExpiryParameter.Descriptor,
            ValidateClientCredentialsParameters.Descriptor,
            ValidateScopes.Descriptor,
            ValidateAuthentication.Descriptor,
            ValidateEndpointPermissions.Descriptor,
            ValidateGrantTypePermissions.Descriptor,
            ValidateScopePermissions.Descriptor,
            ValidateSignedRequestRequirement.Descriptor,
            ValidateTokenDeliveryMode.Descriptor,
            ValidateUserCodeParameter.Descriptor,

            /*
             * Backchannel authentication request handling:
             */
            AttachPrincipal.Descriptor,

            /*
             * Backchannel authentication sign-in processing:
             */
            AttachBackchannelNotificationProperties.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for extracting backchannel authentication requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractBackchannelAuthenticationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractBackchannelAuthenticationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireBackchannelAuthenticationRequest>()
                    .UseSingletonHandler<ExtractBackchannelAuthenticationRequest>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ExtractBackchannelAuthenticationRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                if (notification.Request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0532));
                }

                context.Logger.LogInformation(6300, SR.GetResourceString(SR.ID6300), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating backchannel authentication requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateBackchannelAuthenticationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateBackchannelAuthenticationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireBackchannelAuthenticationRequest>()
                    .UseSingletonHandler<ValidateBackchannelAuthenticationRequest>()
                    .SetOrder(ExtractBackchannelAuthenticationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ValidateBackchannelAuthenticationRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by handlers
                // that want to access the identity token hint principal without triggering a new validation.
                context.Transaction.SetProperty(typeof(ValidateBackchannelAuthenticationRequestContext).FullName!, notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                context.Logger.LogInformation(6301, SR.GetResourceString(SR.ID6301));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling backchannel authentication requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleBackchannelAuthenticationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleBackchannelAuthenticationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireBackchannelAuthenticationRequest>()
                    .UseSingletonHandler<HandleBackchannelAuthenticationRequest>()
                    .SetOrder(ValidateBackchannelAuthenticationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new HandleBackchannelAuthenticationRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                // Unlike other endpoints, the backchannel authentication endpoint requires identifying the end user:
                // since OpenIddict cannot resolve the user from the hints itself, a principal MUST be attached by
                // the application (typically using the pass-through mode or a custom event handler).
                if (notification.Principal is not { Identity.IsAuthenticated: true } principal ||
                    string.IsNullOrEmpty(principal.GetClaim(Claims.Subject)))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0531));
                }

                var @event = new ProcessSignInContext(context.Transaction)
                {
                    Principal = principal,
                    Response = new OpenIddictResponse()
                };

                if (notification.Parameters.Count is > 0)
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

                if (@event.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (@event.IsRejected)
                {
                    context.Reject(
                        error: @event.Error ?? Errors.InvalidGrant,
                        description: @event.ErrorDescription,
                        uri: @event.ErrorUri);
                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing backchannel authentication responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyBackchannelAuthenticationResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyBackchannelAuthenticationResponse(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireBackchannelAuthenticationRequest>()
                    .UseSingletonHandler<ApplyBackchannelAuthenticationResponse<TContext>>()
                    .SetOrder(500_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ApplyBackchannelAuthenticationResponseContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0533));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting backchannel authentication requests that specify the request
        /// parameter when signed authentication requests are not enabled and for validating signed authentication
        /// requests and replacing the request parameters by the parameters contained in the signed request.
        /// </summary>
        public sealed class ValidateRequestParameter : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateRequestParameter(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateBackchannelAuthenticationRequestContext>()
                    .UseSingletonHandler<ValidateRequestParameter>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (string.IsNullOrEmpty(context.Request.Request))
                {
                    return;
                }

                if (!context.Options.EnableSignedBackchannelAuthenticationRequests)
                {
                    context.Reject(
                        error: Errors.RequestNotSupported,
                        description: SR.FormatID2028(Parameters.Request),
                        uri: SR.FormatID8000(SR.ID2028));

                    return;
                }

                // The client identifier is required to resolve the keys used to validate the signed request.
                if (string.IsNullOrEmpty(context.Request.ClientId))
                {
                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.FormatID2029(Parameters.ClientId),
                        uri: SR.FormatID8000(SR.ID2029));

                    return;
                }

                // When a signed authentication request is used, the authentication request parameters MUST NOT be present
                // outside of the JWT (only the client authentication parameters are allowed as regular parameters).
                //
                // See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1.
                foreach (var parameter in context.Request.GetParameters())
                {
                    if (parameter.Key is not (Parameters.Request or Parameters.ClientId or Parameters.ClientSecret or
                                              Parameters.ClientAssertion or Parameters.ClientAssertionType))
                    {
                        context.Logger.LogInformation(6400, SR.GetResourceString(SR.ID6400), parameter.Key);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2300(parameter.Key),
                            uri: SR.FormatID8000(SR.ID2300));

                        return;
                    }
                }

                var (principal, request, algorithm) = await Authentication.ValidateRequestObjectAsync(
                    context, _dispatcher, context.Request);
                if (principal is null || request is null)
                {
                    // Note: signed backchannel authentication request validation errors are returned
                    // using the generic invalid_request error, as invalid_request_object is not defined
                    // by the CIBA specification for the backchannel authentication endpoint.
                    if (context.IsRejected && context.Error is Errors.InvalidRequestObject)
                    {
                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: context.ErrorDescription,
                            uri: context.ErrorUri);
                    }

                    return;
                }

                // Signed authentication requests MUST contain the "exp", "iat", "nbf" and "jti" claims.
                //
                // See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1.
                foreach (var name in (string[]) [Claims.ExpiresAt, Claims.IssuedAt, Claims.NotBefore, Claims.JwtId])
                {
                    if (!principal.HasClaim(name) && !HasRegisteredClaim(principal, name))
                    {
                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2212(name),
                            uri: SR.FormatID8000(SR.ID2212));

                        return;
                    }
                }

                // Reject signed requests that are not valid yet.
                if (principal.GetClaim(Claims.NotBefore) is string value &&
                    long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long nbf) &&
                    DateTimeOffset.FromUnixTimeSeconds(nbf) > context.Options.TimeProvider.GetUtcNow() +
                        context.Options.TokenValidationParameters.ClockSkew)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2212(Claims.NotBefore),
                        uri: SR.FormatID8000(SR.ID2212));

                    return;
                }

                context.Request = request;
                context.RequestObjectPrincipal = principal;
                context.RequestObjectSigningAlgorithm = algorithm;

                static bool HasRegisteredClaim(ClaimsPrincipal principal, string name) => name switch
                {
                    // Note: the "exp", "iat" and "jti" claims are mapped to internal claims when validating tokens.
                    Claims.ExpiresAt => principal.GetExpirationDate() is not null,
                    Claims.IssuedAt  => principal.GetCreationDate() is not null,
                    Claims.JwtId     => !string.IsNullOrEmpty(principal.GetTokenId()),
                    _                => false
                };
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting backchannel authentication requests that don't specify a valid scope parameter.
        /// </summary>
        public sealed class ValidateScopeParameter : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateBackchannelAuthenticationRequestContext>()
                    .UseSingletonHandler<ValidateScopeParameter>()
                    .SetOrder(ValidateRequestParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Backchannel authentication requests MUST contain the "openid" scope.
                //
                // See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.
                if (!context.Request.HasScope(Scopes.OpenId))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2215),
                        uri: SR.FormatID8000(SR.ID2215));

                    return ValueTask.CompletedTask;
                }

                // Reject requests that specify scope=offline_access if the refresh token flow is not enabled.
                if (context.Request.HasScope(Scopes.OfflineAccess) && !context.Options.GrantTypes.Contains(GrantTypes.RefreshToken))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2035(Scopes.OfflineAccess),
                        uri: SR.FormatID8000(SR.ID2035));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting backchannel authentication requests that don't specify exactly one hint.
        /// </summary>
        public sealed class ValidateHintParameters : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateBackchannelAuthenticationRequestContext>()
                    .UseSingletonHandler<ValidateHintParameters>()
                    .SetOrder(ValidateScopeParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Backchannel authentication requests MUST contain one and only one of the login_hint_token,
                // id_token_hint or login_hint parameters, that are used to identify the end user.
                //
                // See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.
                var count = (string.IsNullOrEmpty(context.Request.LoginHint)      ? 0 : 1) +
                            (string.IsNullOrEmpty(context.Request.LoginHintToken) ? 0 : 1) +
                            (string.IsNullOrEmpty(context.Request.IdTokenHint)    ? 0 : 1);

                if (count is not 1)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2214),
                        uri: SR.FormatID8000(SR.ID2214));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting backchannel authentication requests that specify an invalid requested_expiry.
        /// </summary>
        public sealed class ValidateRequestedExpiryParameter : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateBackchannelAuthenticationRequestContext>()
                    .UseSingletonHandler<ValidateRequestedExpiryParameter>()
                    .SetOrder(ValidateHintParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.Request.HasParameter(Parameters.RequestedExpiry) && context.Request.RequestedExpiry is not > 0)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2052(Parameters.RequestedExpiry),
                        uri: SR.FormatID8000(SR.ID2052));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting backchannel authentication requests that specify invalid client credentials parameters.
        /// </summary>
        public sealed class ValidateClientCredentialsParameters : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateBackchannelAuthenticationRequestContext>()
                    .UseSingletonHandler<ValidateClientCredentialsParameters>()
                    .SetOrder(ValidateRequestedExpiryParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Ensure a client_assertion_type is specified when a client_assertion was attached.
                if (!string.IsNullOrEmpty(context.Request.ClientAssertion) &&
                     string.IsNullOrEmpty(context.Request.ClientAssertionType))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2037(Parameters.ClientAssertionType, Parameters.ClientAssertion),
                        uri: SR.FormatID8000(SR.ID2037));

                    return ValueTask.CompletedTask;
                }

                // Ensure a client_assertion is specified when a client_assertion_type was attached.
                if (string.IsNullOrEmpty(context.Request.ClientAssertion) &&
                   !string.IsNullOrEmpty(context.Request.ClientAssertionType))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2037(Parameters.ClientAssertion, Parameters.ClientAssertionType),
                        uri: SR.FormatID8000(SR.ID2037));

                    return ValueTask.CompletedTask;
                }

                // Reject requests that use multiple client authentication methods.
                //
                // See https://tools.ietf.org/html/rfc6749#section-2.3 for more information.
                if (!string.IsNullOrEmpty(context.Request.ClientAssertion) &&
                    !string.IsNullOrEmpty(context.Request.ClientSecret))
                {
                    context.Logger.LogInformation(6140, SR.GetResourceString(SR.ID6140));

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2087),
                        uri: SR.FormatID8000(SR.ID2087));

                    return ValueTask.CompletedTask;
                }

                // Ensure the specified client_assertion_type is supported.
                if (!string.IsNullOrEmpty(context.Request.ClientAssertionType) &&
                    !context.Options.ClientAssertionTypes.Contains(context.Request.ClientAssertionType))
                {
                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.FormatID2032(Parameters.ClientAssertionType),
                        uri: SR.FormatID8000(SR.ID2032));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting backchannel authentication requests that use unregistered scopes.
        /// Note: this handler partially works with the degraded mode but is not used when scope validation is disabled.
        /// </summary>
        public sealed class ValidateScopes : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateBackchannelAuthenticationRequestContext>()
                    .AddFilter<RequireScopeValidationEnabled>()
                    .UseSingletonHandler<ValidateScopes>()
                    .SetOrder(ValidateClientCredentialsParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // If all the specified scopes are registered in the options, avoid making a database lookup.
                var scopes = context.Request.GetScopes().ToHashSet(StringComparer.Ordinal);
                scopes.ExceptWith(context.Options.Scopes);

                if (scopes.Count is not 0 && !context.Options.EnableDegradedMode)
                {
                    var manager = context.ServiceProvider.GetService<IOpenIddictScopeManager>()
                        ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                    await foreach (var scope in manager.FindByNamesAsync([.. scopes], context.CancellationToken))
                    {
                        var name = await manager.GetNameAsync(scope, context.CancellationToken);
                        if (!string.IsNullOrEmpty(name))
                        {
                            scopes.Remove(name);
                        }
                    }
                }

                // If at least one scope was not recognized, return an error.
                if (scopes.Count is not 0)
                {
                    context.Logger.LogInformation(6305, SR.GetResourceString(SR.ID6305), scopes);

                    context.Reject(
                        error: Errors.InvalidScope,
                        description: SR.FormatID2052(Parameters.Scope),
                        uri: SR.FormatID8000(SR.ID2052));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for applying the authentication logic to backchannel authentication requests.
        /// </summary>
        public sealed class ValidateAuthentication : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateAuthentication(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateBackchannelAuthenticationRequestContext>()
                    .UseSingletonHandler<ValidateAuthentication>()
                    .SetOrder(ValidateScopes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

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

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                // Attach the security principal extracted from the identity token hint to the validation context.
                context.IdentityTokenHintPrincipal = notification.IdentityTokenPrincipal;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting backchannel authentication requests made by applications
        /// that haven't been granted the backchannel authentication endpoint permission.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateEndpointPermissions : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateBackchannelAuthenticationRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireEndpointPermissionsEnabled>()
                    .UseSingletonHandler<ValidateEndpointPermissions>()
                    .SetOrder(ValidateAuthentication.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var manager = context.ServiceProvider.GetService<IOpenIddictApplicationManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var application = await manager.FindByClientIdAsync(context.ClientId, context.CancellationToken)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                if (!await manager.HasPermissionAsync(application, Permissions.Endpoints.BackchannelAuthentication, context.CancellationToken))
                {
                    context.Logger.LogInformation(6302, SR.GetResourceString(SR.ID6302), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2217),
                        uri: SR.FormatID8000(SR.ID2217));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting backchannel authentication requests made by unauthorized applications.
        /// Note: this handler is not used when the degraded mode is enabled or when grant type permissions are disabled.
        /// </summary>
        public sealed class ValidateGrantTypePermissions : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateBackchannelAuthenticationRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireGrantTypePermissionsEnabled>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseSingletonHandler<ValidateGrantTypePermissions>()
                    .SetOrder(ValidateEndpointPermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var manager = context.ServiceProvider.GetService<IOpenIddictApplicationManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var application = await manager.FindByClientIdAsync(context.ClientId, context.CancellationToken)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // Reject the request if the application is not allowed to use the CIBA grant.
                if (!await manager.HasPermissionAsync(application, Permissions.GrantTypes.Ciba, context.CancellationToken))
                {
                    context.Logger.LogInformation(6303, SR.GetResourceString(SR.ID6303), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2218),
                        uri: SR.FormatID8000(SR.ID2218));

                    return;
                }

                // Reject the request if the offline_access scope was request and
                // if the application is not allowed to use the refresh token grant.
                if (context.Request.HasScope(Scopes.OfflineAccess) &&
                   !await manager.HasPermissionAsync(application, Permissions.GrantTypes.RefreshToken, context.CancellationToken))
                {
                    context.Logger.LogInformation(6304, SR.GetResourceString(SR.ID6304), context.ClientId, Scopes.OfflineAccess);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2065(Scopes.OfflineAccess),
                        uri: SR.FormatID8000(SR.ID2065));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting backchannel authentication requests made by applications
        /// that haven't been granted the appropriate scope permissions.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateScopePermissions : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateBackchannelAuthenticationRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireScopePermissionsEnabled>()
                    .UseSingletonHandler<ValidateScopePermissions>()
                    .SetOrder(ValidateGrantTypePermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var manager = context.ServiceProvider.GetService<IOpenIddictApplicationManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var application = await manager.FindByClientIdAsync(context.ClientId, context.CancellationToken)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                foreach (var scope in context.Request.GetScopes())
                {
                    // Avoid validating the "openid" and "offline_access" scopes as they represent protocol scopes.
                    if (string.Equals(scope, Scopes.OfflineAccess, StringComparison.Ordinal) ||
                        string.Equals(scope, Scopes.OpenId, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    // Reject the request if the application is not allowed to use the iterated scope.
                    if (!await manager.HasPermissionAsync(application, Permissions.Prefixes.Scope + scope, context.CancellationToken))
                    {
                        context.Logger.LogInformation(6304, SR.GetResourceString(SR.ID6304), context.ClientId, scope);

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
        /// Contains the logic responsible for rejecting unsigned backchannel authentication requests sent by client
        /// applications registered with a backchannel authentication request signing algorithm.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateSignedRequestRequirement : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateBackchannelAuthenticationRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseSingletonHandler<ValidateSignedRequestRequirement>()
                    .SetOrder(ValidateScopePermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                // Note: when signed requests are not enabled, the request parameter is always rejected and
                // the signing algorithm registered by the client application (if any) is not enforced.
                if (!context.Options.EnableSignedBackchannelAuthenticationRequests)
                {
                    return;
                }

                var manager = context.ServiceProvider.GetService<IOpenIddictApplicationManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var application = await manager.FindByClientIdAsync(context.ClientId, context.CancellationToken)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                var settings = await manager.GetSettingsAsync(application, context.CancellationToken);
                if (!settings.TryGetValue(Settings.BackchannelAuthentication.RequestSigningAlgorithm, out string? algorithm) ||
                    string.IsNullOrEmpty(algorithm))
                {
                    return;
                }

                // If the client application registered a backchannel_authentication_request_signing_alg value,
                // unsigned requests or requests signed using a different algorithm MUST be rejected.
                //
                // See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4.
                if (context.RequestObjectPrincipal is null ||
                    !string.Equals(context.RequestObjectSigningAlgorithm, algorithm, StringComparison.Ordinal))
                {
                    context.Logger.LogInformation(6401, SR.GetResourceString(SR.ID6401), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2301),
                        uri: SR.FormatID8000(SR.ID2301));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for resolving the token delivery mode registered for the client
        /// application and rejecting requests that don't satisfy the requirements of that delivery mode.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateTokenDeliveryMode : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateBackchannelAuthenticationRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseSingletonHandler<ValidateTokenDeliveryMode>()
                    .SetOrder(ValidateSignedRequestRequirement.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                // Note: when only the poll mode is enabled, the delivery mode registered by
                // the client application is not resolved and the poll mode is always used.
                if (context.Options.BackchannelTokenDeliveryModes.Count is 1 &&
                    context.Options.BackchannelTokenDeliveryModes.Contains(BackchannelTokenDeliveryModes.Poll))
                {
                    context.TokenDeliveryMode = BackchannelTokenDeliveryModes.Poll;

                    return;
                }

                var manager = context.ServiceProvider.GetService<IOpenIddictApplicationManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var application = await manager.FindByClientIdAsync(context.ClientId, context.CancellationToken)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                var settings = await manager.GetSettingsAsync(application, context.CancellationToken);

                // Note: client applications that don't have a registered token delivery mode are treated as poll clients.
                var mode = settings.TryGetValue(Settings.BackchannelAuthentication.TokenDeliveryMode, out string? value) &&
                    !string.IsNullOrEmpty(value) ? value : BackchannelTokenDeliveryModes.Poll;

                if (!context.Options.BackchannelTokenDeliveryModes.Contains(mode))
                {
                    context.Logger.LogInformation(6402, SR.GetResourceString(SR.ID6402), context.ClientId, mode);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.FormatID2302(mode),
                        uri: SR.FormatID8000(SR.ID2302));

                    return;
                }

                if (mode is BackchannelTokenDeliveryModes.Ping or BackchannelTokenDeliveryModes.Push)
                {
                    // Clients using the ping or push modes MUST register a client notification endpoint, that
                    // must use TLS as it receives bearer notification tokens (and tokens, for the push mode).
                    //
                    // See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4.
                    if (!settings.TryGetValue(Settings.BackchannelAuthentication.ClientNotificationEndpoint, out string? endpoint) ||
                        !Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) ||
                        !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                        !string.IsNullOrEmpty(uri.Fragment))
                    {
                        context.Logger.LogWarning(6403, SR.GetResourceString(SR.ID6403), context.ClientId);

                        context.Reject(
                            error: Errors.UnauthorizedClient,
                            description: SR.GetResourceString(SR.ID2303),
                            uri: SR.FormatID8000(SR.ID2303));

                        return;
                    }

                    // The client_notification_token parameter is REQUIRED for clients using the ping or push modes
                    // and MUST NOT exceed 1024 characters. For more information, see
                    // https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.
                    if (string.IsNullOrEmpty(context.Request.ClientNotificationToken))
                    {
                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2029(Parameters.ClientNotificationToken),
                            uri: SR.FormatID8000(SR.ID2029));

                        return;
                    }

                    if (context.Request.ClientNotificationToken.Length > 1024)
                    {
                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2052(Parameters.ClientNotificationToken),
                            uri: SR.FormatID8000(SR.ID2052));

                        return;
                    }
                }

                // Tokens delivered using the push mode are generated outside the context of a token request and
                // thus can't be bound to a DPoP proof key or to the TLS client certificate used by the client.
                // To prevent a silent downgrade to bearer tokens, reject push clients that require DPoP or
                // that authenticated using a client certificate when certificate-bound tokens are enabled.
                //
                // See https://datatracker.ietf.org/doc/html/rfc9449#section-5 and
                // https://datatracker.ietf.org/doc/html/rfc8705#section-3.
                if (mode is BackchannelTokenDeliveryModes.Push &&
                   ((context.Options.UseClientCertificateBoundAccessTokens && context.Transaction.RemoteCertificate is not null) ||
                    await manager.HasRequirementAsync(application, Requirements.Features.DPoP, context.CancellationToken)))
                {
                    context.Logger.LogInformation(6416, SR.GetResourceString(SR.ID6416), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2312),
                        uri: SR.FormatID8000(SR.ID2312));

                    return;
                }

                context.TokenDeliveryMode = mode;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting backchannel authentication requests that don't specify
        /// a user code when the client application is registered as supporting the "user_code" parameter.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateUserCodeParameter : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateBackchannelAuthenticationRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseSingletonHandler<ValidateUserCodeParameter>()
                    .SetOrder(ValidateTokenDeliveryMode.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                // Note: the user code itself can only be validated by the application (e.g using a custom
                // event handler or the pass-through mode), that is expected to return invalid_user_code errors.
                if (!context.Options.EnableBackchannelUserCodeParameter || !string.IsNullOrEmpty(context.Request.UserCode))
                {
                    return;
                }

                var manager = context.ServiceProvider.GetService<IOpenIddictApplicationManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var application = await manager.FindByClientIdAsync(context.ClientId, context.CancellationToken)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // If both the server and the client support the user_code parameter, a user code MUST be sent.
                //
                // See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13.
                var settings = await manager.GetSettingsAsync(application, context.CancellationToken);
                if (settings.TryGetValue(Settings.BackchannelAuthentication.UserCodeParameter, out string? value) &&
                    bool.TryParse(value, out bool supported) && supported)
                {
                    context.Reject(
                        error: Errors.MissingUserCode,
                        description: SR.FormatID2029(Parameters.UserCode),
                        uri: SR.FormatID8000(SR.ID2029));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for storing the information needed to send ping or push notifications
        /// (i.e the authentication request identifier and the client notification token) in the token entry
        /// of the authentication request identifier, as an encrypted token only readable by the server.
        /// Note: this handler is not used when the degraded mode is enabled or when token storage is disabled.
        /// </summary>
        public sealed class AttachBackchannelNotificationProperties : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireBackchannelAuthenticationRequest>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireAuthenticationRequestIdGenerated>()
                    .UseSingletonHandler<AttachBackchannelNotificationProperties>()
                    .SetOrder(GenerateAuthenticationRequestId.Descriptor.Order + 250)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessSignInContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = context.Transaction.GetProperty<ValidateBackchannelAuthenticationRequestContext>(
                    typeof(ValidateBackchannelAuthenticationRequestContext).FullName!);

                if (notification?.TokenDeliveryMode is not (BackchannelTokenDeliveryModes.Ping or BackchannelTokenDeliveryModes.Push) ||
                    string.IsNullOrEmpty(context.Request.ClientNotificationToken))
                {
                    return;
                }

                // Note: the raw authentication request identifier is not stored in the database (only a hash is),
                // but it must be sent to the client notification endpoint once the request is completed. To support
                // that, the identifier and the client notification token are stored as an encrypted token.
                if (string.IsNullOrEmpty(context.AuthenticationRequestId) ||
                    context.AuthenticationRequestIdPrincipal?.GetTokenId() is not { Length: > 0 } identifier)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0602));
                }

                var manager = context.ServiceProvider.GetService<IOpenIddictTokenManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var token = await manager.FindByIdAsync(identifier, context.CancellationToken)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0602));

                var payload = await OpenIddictServerService.CreateBackchannelNotificationPayloadAsync(context.Transaction,
                    context.AuthenticationRequestId, context.Request.ClientNotificationToken, notification.TokenDeliveryMode,
                    context.AuthenticationRequestIdPrincipal.GetExpirationDate());

                var descriptor = new OpenIddictTokenDescriptor();
                await manager.PopulateAsync(descriptor, token, context.CancellationToken);

                descriptor.Properties[Properties.BackchannelNotification] = JsonSerializer.SerializeToElement(
                    payload, OpenIddictSerializer.Default.String);

                await manager.UpdateAsync(token, descriptor, context.CancellationToken);

                context.Logger.LogDebug(6404, SR.GetResourceString(SR.ID6404), identifier, notification.TokenDeliveryMode);
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the principal
        /// extracted from the identity token hint to the event context.
        /// </summary>
        public sealed class AttachPrincipal : IOpenIddictServerHandler<HandleBackchannelAuthenticationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleBackchannelAuthenticationRequestContext>()
                    .UseSingletonHandler<AttachPrincipal>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = context.Transaction.GetProperty<ValidateBackchannelAuthenticationRequestContext>(
                    typeof(ValidateBackchannelAuthenticationRequestContext).FullName!)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

                context.IdentityTokenHintPrincipal ??= notification.IdentityTokenHintPrincipal;

                return ValueTask.CompletedTask;
            }
        }
    }
}
