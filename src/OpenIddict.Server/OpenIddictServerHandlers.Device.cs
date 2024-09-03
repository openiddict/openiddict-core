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
using Microsoft.Extensions.Options;
using OpenIddict.Extensions;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    public static class Device
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Device request top-level processing:
             */
            ExtractDeviceAuthorizationRequest.Descriptor,
            ValidateDeviceAuthorizationRequest.Descriptor,
            HandleDeviceAuthorizationRequest.Descriptor,
            ApplyDeviceAuthorizationResponse<ProcessChallengeContext>.Descriptor,
            ApplyDeviceAuthorizationResponse<ProcessErrorContext>.Descriptor,
            ApplyDeviceAuthorizationResponse<ProcessRequestContext>.Descriptor,
            ApplyDeviceAuthorizationResponse<ProcessSignInContext>.Descriptor,

            /*
             * Device request validation:
             */
            ValidateScopeParameter.Descriptor,
            ValidateClientCredentialsParameters.Descriptor,
            ValidateScopes.Descriptor,
            ValidateDeviceAuthentication.Descriptor,
            ValidateEndpointPermissions.Descriptor,
            ValidateGrantTypePermissions.Descriptor,
            ValidateScopePermissions.Descriptor,

            /*
             * Verification request top-level processing:
             */
            ExtractEndUserVerificationRequest.Descriptor,
            ValidateEndUserVerificationRequest.Descriptor,
            HandleEndUserVerificationRequest.Descriptor,
            ApplyEndUserVerificationResponse<ProcessChallengeContext>.Descriptor,
            ApplyEndUserVerificationResponse<ProcessErrorContext>.Descriptor,
            ApplyEndUserVerificationResponse<ProcessRequestContext>.Descriptor,
            ApplyEndUserVerificationResponse<ProcessSignInContext>.Descriptor,

            /*
             * Verification request validation:
             */
            ValidateVerificationAuthentication.Descriptor,

            /*
             * Verification request handling:
             */
            AttachUserCodePrincipal.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for extracting device requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractDeviceAuthorizationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractDeviceAuthorizationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireDeviceAuthorizationRequest>()
                    .UseScopedHandler<ExtractDeviceAuthorizationRequest>()
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

                var notification = new ExtractDeviceAuthorizationRequestContext(context.Transaction);
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
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0031));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6054), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating device requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateDeviceAuthorizationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateDeviceAuthorizationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireDeviceAuthorizationRequest>()
                    .UseScopedHandler<ValidateDeviceAuthorizationRequest>()
                    .SetOrder(ExtractDeviceAuthorizationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ValidateDeviceAuthorizationRequestContext(context.Transaction);
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6055));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling device requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleDeviceAuthorizationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleDeviceAuthorizationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireDeviceAuthorizationRequest>()
                    .UseScopedHandler<HandleDeviceAuthorizationRequest>()
                    .SetOrder(ValidateDeviceAuthorizationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new HandleDeviceAuthorizationRequestContext(context.Transaction);
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

                if (notification.Principal is null)
                {
                    // Note: no authentication type is deliberately specified to represent an unauthenticated identity.
                    var principal = new ClaimsPrincipal(new ClaimsIdentity());
                    principal.SetScopes(notification.Request.GetScopes());

                    notification.Principal = principal;
                }

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
                        error: @event.Error ?? Errors.InvalidGrant,
                        description: @event.ErrorDescription,
                        uri: @event.ErrorUri);
                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing sign-in responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyDeviceAuthorizationResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyDeviceAuthorizationResponse(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireDeviceAuthorizationRequest>()
                    .UseScopedHandler<ApplyDeviceAuthorizationResponse<TContext>>()
                    .SetOrder(500_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ApplyDeviceAuthorizationResponseContext(context.Transaction);
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0033));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting device requests that don't specify a valid scope parameter.
        /// </summary>
        public sealed class ValidateScopeParameter : IOpenIddictServerHandler<ValidateDeviceAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceAuthorizationRequestContext>()
                    .UseSingletonHandler<ValidateScopeParameter>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateDeviceAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reject device requests that specify scope=offline_access if the refresh token flow is not enabled.
                if (context.Request.HasScope(Scopes.OfflineAccess) && !context.Options.GrantTypes.Contains(GrantTypes.RefreshToken))
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
        /// Contains the logic responsible for rejecting device requests that specify invalid client credentials parameters.
        /// </summary>
        public sealed class ValidateClientCredentialsParameters : IOpenIddictServerHandler<ValidateDeviceAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceAuthorizationRequestContext>()
                    .UseSingletonHandler<ValidateClientCredentialsParameters>()
                    .SetOrder(ValidateScopeParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateDeviceAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Ensure a client_assertion_type is specified when a client_assertion was attached.
                if (!string.IsNullOrEmpty(context.Request.ClientAssertion) &&
                     string.IsNullOrEmpty(context.Request.ClientAssertionType))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2037(Parameters.ClientAssertionType, Parameters.ClientAssertion),
                        uri: SR.FormatID8000(SR.ID2037));

                    return default;
                }

                // Ensure a client_assertion is specified when a client_assertion_type was attached.
                if (string.IsNullOrEmpty(context.Request.ClientAssertion) &&
                   !string.IsNullOrEmpty(context.Request.ClientAssertionType))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2037(Parameters.ClientAssertion, Parameters.ClientAssertionType),
                        uri: SR.FormatID8000(SR.ID2037));

                    return default;
                }

                // Reject requests that use multiple client authentication methods.
                //
                // See https://tools.ietf.org/html/rfc6749#section-2.3 for more information.
                if (!string.IsNullOrEmpty(context.Request.ClientAssertion) &&
                    !string.IsNullOrEmpty(context.Request.ClientSecret))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6140));

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2087),
                        uri: SR.FormatID8000(SR.ID2087));

                    return default;
                }

                // Ensure the specified client_assertion_type is supported.
                if (!string.IsNullOrEmpty(context.Request.ClientAssertionType) &&
                    !context.Options.ClientAssertionTypes.Contains(context.Request.ClientAssertionType))
                {
                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.FormatID2032(Parameters.ClientAssertionType),
                        uri: SR.FormatID8000(SR.ID2032));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that use unregistered scopes.
        /// Note: this handler partially works with the degraded mode but is not used when scope validation is disabled.
        /// </summary>
        public sealed class ValidateScopes : IOpenIddictServerHandler<ValidateDeviceAuthorizationRequestContext>
        {
            private readonly IOpenIddictScopeManager? _scopeManager;

            public ValidateScopes(IOpenIddictScopeManager? scopeManager = null)
                => _scopeManager = scopeManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceAuthorizationRequestContext>()
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
                    .SetOrder(ValidateClientCredentialsParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateDeviceAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If all the specified scopes are registered in the options, avoid making a database lookup.
                var scopes = context.Request.GetScopes().ToHashSet(StringComparer.Ordinal);
                scopes.ExceptWith(context.Options.Scopes);

                // Note: the remaining scopes are only checked if the degraded mode was not enabled,
                // as this requires using the scope manager, which is never used with the degraded mode,
                // even if the service was registered and resolved from the dependency injection container.
                if (scopes.Count is not 0 && !context.Options.EnableDegradedMode)
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
                if (scopes.Count is not 0)
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6057), scopes);

                    context.Reject(
                        error: Errors.InvalidScope,
                        description: SR.FormatID2052(Parameters.Scope),
                        uri: SR.FormatID8000(SR.ID2052));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for applying the authentication logic to device requests.
        /// </summary>
        public sealed class ValidateDeviceAuthentication : IOpenIddictServerHandler<ValidateDeviceAuthorizationRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateDeviceAuthentication(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceAuthorizationRequestContext>()
                    .UseScopedHandler<ValidateDeviceAuthentication>()
                    .SetOrder(ValidateScopes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateDeviceAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
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
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting device requests made by
        /// applications that haven't been granted the device authorization endpoint permission.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateEndpointPermissions : IOpenIddictServerHandler<ValidateDeviceAuthorizationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateEndpointPermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateEndpointPermissions(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceAuthorizationRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireEndpointPermissionsEnabled>()
                    .UseScopedHandler<ValidateEndpointPermissions>()
                    .SetOrder(ValidateDeviceAuthentication.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateDeviceAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // Reject the request if the application is not allowed to use the device authorization endpoint.
                //
                // Note: the legacy "ept:device" permission is still allowed for backward compatibility.
                if (!await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.DeviceAuthorization) &&
                    !await _applicationManager.HasPermissionAsync(application, "ept:device"))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6062), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2056),
                        uri: SR.FormatID8000(SR.ID2056));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting device requests made by unauthorized applications.
        /// Note: this handler is not used when the degraded mode is enabled or when grant type permissions are disabled.
        /// </summary>
        public sealed class ValidateGrantTypePermissions : IOpenIddictServerHandler<ValidateDeviceAuthorizationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateGrantTypePermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateGrantTypePermissions(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceAuthorizationRequestContext>()
                    .AddFilter<RequireGrantTypePermissionsEnabled>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateGrantTypePermissions>()
                    .SetOrder(ValidateEndpointPermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateDeviceAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // Reject the request if the application is not allowed to use the device code grant.
                if (!await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.DeviceCode))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6118), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2027),
                        uri: SR.FormatID8000(SR.ID2027));

                    return;
                }

                // Reject the request if the offline_access scope was request and
                // if the application is not allowed to use the refresh token grant.
                if (context.Request.HasScope(Scopes.OfflineAccess) &&
                   !await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.RefreshToken))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6120), context.ClientId, Scopes.OfflineAccess);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2065(Scopes.OfflineAccess),
                        uri: SR.FormatID8000(SR.ID2065));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting device requests made by applications
        /// that haven't been granted the appropriate grant type permission.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateScopePermissions : IOpenIddictServerHandler<ValidateDeviceAuthorizationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateScopePermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateScopePermissions(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceAuthorizationRequestContext>()
                    .AddFilter<RequireClientIdParameter>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireScopePermissionsEnabled>()
                    .UseScopedHandler<ValidateScopePermissions>()
                    .SetOrder(ValidateGrantTypePermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateDeviceAuthorizationRequestContext context)
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
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6063), context.ClientId, scope);

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
        /// Contains the logic responsible for extracting end-user verification requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractEndUserVerificationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractEndUserVerificationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireEndUserVerificationRequest>()
                    .UseScopedHandler<ExtractEndUserVerificationRequest>()
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

                var notification = new ExtractEndUserVerificationRequestContext(context.Transaction);
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
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0034));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6064), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating end-user verification requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateEndUserVerificationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateEndUserVerificationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireEndUserVerificationRequest>()
                    .UseScopedHandler<ValidateEndUserVerificationRequest>()
                    .SetOrder(ExtractEndUserVerificationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ValidateEndUserVerificationRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by handlers
                // that want to access the context without triggering a new validation process.
                context.Transaction.SetProperty(typeof(ValidateEndUserVerificationRequestContext).FullName!, notification);

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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6065));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling end-user verification requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleEndUserVerificationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleEndUserVerificationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireEndUserVerificationRequest>()
                    .UseScopedHandler<HandleEndUserVerificationRequest>()
                    .SetOrder(ValidateEndUserVerificationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new HandleEndUserVerificationRequestContext(context.Transaction);
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
                            error: @event.Error ?? Errors.InvalidGrant,
                            description: @event.ErrorDescription,
                            uri: @event.ErrorUri);
                        return;
                    }
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0035));
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing sign-in responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyEndUserVerificationResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyEndUserVerificationResponse(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireEndUserVerificationRequest>()
                    .UseScopedHandler<ApplyEndUserVerificationResponse<TContext>>()
                    .SetOrder(500_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ApplyEndUserVerificationResponseContext(context.Transaction);
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0036));
            }
        }

        /// <summary>
        /// Contains the logic responsible for applying the authentication logic to end-user verification requests.
        /// </summary>
        public sealed class ValidateVerificationAuthentication : IOpenIddictServerHandler<ValidateEndUserVerificationRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateVerificationAuthentication(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateEndUserVerificationRequestContext>()
                    .UseScopedHandler<ValidateVerificationAuthentication>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateEndUserVerificationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
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
                context.Principal = notification.UserCodePrincipal;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the principal extracted from the user code to the event context.
        /// </summary>
        public sealed class AttachUserCodePrincipal : IOpenIddictServerHandler<HandleEndUserVerificationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleEndUserVerificationRequestContext>()
                    .UseSingletonHandler<AttachUserCodePrincipal>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleEndUserVerificationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = context.Transaction.GetProperty<ValidateEndUserVerificationRequestContext>(
                    typeof(ValidateEndUserVerificationRequestContext).FullName!) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

                context.UserCodePrincipal ??= notification.Principal;

                return default;
            }
        }
    }
}
