/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Claims;
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

            /*
             * Backchannel authentication request handling:
             */
            AttachPrincipal.Descriptor
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
        /// Contains the logic responsible for rejecting backchannel authentication requests that specify the unsupported request parameter.
        /// </summary>
        public sealed class ValidateRequestParameter : IOpenIddictServerHandler<ValidateBackchannelAuthenticationRequestContext>
        {
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
            public ValueTask HandleAsync(ValidateBackchannelAuthenticationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Note: signed authentication requests are not supported yet.
                if (!string.IsNullOrEmpty(context.Request.Request))
                {
                    context.Reject(
                        error: Errors.RequestNotSupported,
                        description: SR.FormatID2028(Parameters.Request),
                        uri: SR.FormatID8000(SR.ID2028));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
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
