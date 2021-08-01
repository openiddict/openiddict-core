/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server
{
    public static partial class OpenIddictServerHandlers
    {
        public static class Device
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Device request top-level processing:
                 */
                ExtractDeviceRequest.Descriptor,
                ValidateDeviceRequest.Descriptor,
                HandleDeviceRequest.Descriptor,
                ApplyDeviceResponse<ProcessChallengeContext>.Descriptor,
                ApplyDeviceResponse<ProcessErrorContext>.Descriptor,
                ApplyDeviceResponse<ProcessRequestContext>.Descriptor,
                ApplyDeviceResponse<ProcessSignInContext>.Descriptor,

                /*
                 * Device request validation:
                 */
                ValidateClientIdParameter.Descriptor,
                ValidateScopeParameter.Descriptor,
                ValidateScopes.Descriptor,
                ValidateClientId.Descriptor,
                ValidateClientType.Descriptor,
                ValidateClientSecret.Descriptor,
                ValidateEndpointPermissions.Descriptor,
                ValidateGrantTypePermissions.Descriptor,
                ValidateScopePermissions.Descriptor,

                /*
                 * Verification request top-level processing:
                 */
                ExtractVerificationRequest.Descriptor,
                ValidateVerificationRequest.Descriptor,
                HandleVerificationRequest.Descriptor,
                ApplyVerificationResponse<ProcessChallengeContext>.Descriptor,
                ApplyVerificationResponse<ProcessErrorContext>.Descriptor,
                ApplyVerificationResponse<ProcessRequestContext>.Descriptor,
                ApplyVerificationResponse<ProcessSignInContext>.Descriptor,

                /*
                 * Verification request handling:
                 */
                AttachUserCodePrincipal.Descriptor);

            /// <summary>
            /// Contains the logic responsible of extracting device requests and invoking the corresponding event handlers.
            /// </summary>
            public class ExtractDeviceRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ExtractDeviceRequest(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .AddFilter<RequireDeviceRequest>()
                        .UseScopedHandler<ExtractDeviceRequest>()
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

                    var notification = new ExtractDeviceRequestContext(context.Transaction);
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
            /// Contains the logic responsible of validating device requests and invoking the corresponding event handlers.
            /// </summary>
            public class ValidateDeviceRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ValidateDeviceRequest(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .AddFilter<RequireDeviceRequest>()
                        .UseScopedHandler<ValidateDeviceRequest>()
                        .SetOrder(ExtractDeviceRequest.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ProcessRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new ValidateDeviceRequestContext(context.Transaction);
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
            /// Contains the logic responsible of handling device requests and invoking the corresponding event handlers.
            /// </summary>
            public class HandleDeviceRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public HandleDeviceRequest(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .AddFilter<RequireDeviceRequest>()
                        .UseScopedHandler<HandleDeviceRequest>()
                        .SetOrder(ValidateDeviceRequest.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ProcessRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new HandleDeviceRequestContext(context.Transaction);
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
            /// Contains the logic responsible of processing sign-in responses and invoking the corresponding event handlers.
            /// </summary>
            public class ApplyDeviceResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ApplyDeviceResponse(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .AddFilter<RequireDeviceRequest>()
                        .UseScopedHandler<ApplyDeviceResponse<TContext>>()
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

                    var notification = new ApplyDeviceResponseContext(context.Transaction);
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
            /// Contains the logic responsible of rejecting device requests that don't specify a client identifier.
            /// </summary>
            public class ValidateClientIdParameter : IOpenIddictServerHandler<ValidateDeviceRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceRequestContext>()
                        .UseSingletonHandler<ValidateClientIdParameter>()
                        .SetOrder(int.MinValue + 100_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(ValidateDeviceRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // client_id is a required parameter and MUST cause an error when missing.
                    // See https://tools.ietf.org/html/rfc8628#section-3.1 for more information.
                    if (string.IsNullOrEmpty(context.ClientId))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6056));

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
            /// Contains the logic responsible of rejecting device requests that don't specify a valid scope parameter.
            /// </summary>
            public class ValidateScopeParameter : IOpenIddictServerHandler<ValidateDeviceRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceRequestContext>()
                        .UseSingletonHandler<ValidateScopeParameter>()
                        .SetOrder(ValidateClientIdParameter.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(ValidateDeviceRequestContext context)
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
            /// Contains the logic responsible of rejecting authorization requests that use unregistered scopes.
            /// Note: this handler partially works with the degraded mode but is not used when scope validation is disabled.
            /// </summary>
            public class ValidateScopes : IOpenIddictServerHandler<ValidateDeviceRequestContext>
            {
                private readonly IOpenIddictScopeManager? _scopeManager;

                public ValidateScopes(IOpenIddictScopeManager? scopeManager = null)
                    => _scopeManager = scopeManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceRequestContext>()
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
                        .SetOrder(ValidateScopeParameter.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ValidateDeviceRequestContext context)
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
            /// Contains the logic responsible of rejecting device requests that use an invalid client_id.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientId : IOpenIddictServerHandler<ValidateDeviceRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientId() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                public ValidateClientId(IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceRequestContext>()
                        .AddFilter<RequireClientIdParameter>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .UseScopedHandler<ValidateClientId>()
                        .SetOrder(ValidateScopes.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ValidateDeviceRequestContext context)
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
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6058), context.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: SR.FormatID2052(Parameters.ClientId),
                            uri: SR.FormatID8000(SR.ID2052));

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting device requests made by applications
            /// whose client type is not compatible with the requested grant type.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientType : IOpenIddictServerHandler<ValidateDeviceRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientType() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                public ValidateClientType(IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceRequestContext>()
                        .AddFilter<RequireClientIdParameter>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .UseScopedHandler<ValidateClientType>()
                        .SetOrder(ValidateClientId.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ValidateDeviceRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application is null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));
                    }

                    if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public))
                    {
                        // Reject device requests containing a client_secret when the client is a public application.
                        if (!string.IsNullOrEmpty(context.ClientSecret))
                        {
                            context.Logger.LogInformation(SR.GetResourceString(SR.ID6059), context.ClientId);

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
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6060), context.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: SR.FormatID2054(Parameters.ClientSecret),
                            uri: SR.FormatID8000(SR.ID2054));

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting device requests specifying an invalid client secret.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientSecret : IOpenIddictServerHandler<ValidateDeviceRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientSecret() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                public ValidateClientSecret(IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceRequestContext>()
                        .AddFilter<RequireClientIdParameter>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .UseScopedHandler<ValidateClientSecret>()
                        .SetOrder(ValidateClientType.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ValidateDeviceRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

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
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6061), context.ClientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: SR.GetResourceString(SR.ID2055),
                            uri: SR.FormatID8000(SR.ID2055));

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting device requests made by
            /// applications that haven't been granted the device endpoint permission.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateEndpointPermissions : IOpenIddictServerHandler<ValidateDeviceRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateEndpointPermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                public ValidateEndpointPermissions(IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceRequestContext>()
                        .AddFilter<RequireClientIdParameter>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .AddFilter<RequireEndpointPermissionsEnabled>()
                        .UseScopedHandler<ValidateEndpointPermissions>()
                        .SetOrder(ValidateClientSecret.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ValidateDeviceRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application is null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));
                    }

                    // Reject the request if the application is not allowed to use the device endpoint.
                    if (!await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.Device))
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
            /// Contains the logic responsible of rejecting device requests made by unauthorized applications.
            /// Note: this handler is not used when the degraded mode is enabled or when grant type permissions are disabled.
            /// </summary>
            public class ValidateGrantTypePermissions : IOpenIddictServerHandler<ValidateDeviceRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateGrantTypePermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                public ValidateGrantTypePermissions(IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceRequestContext>()
                        .AddFilter<RequireGrantTypePermissionsEnabled>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .UseScopedHandler<ValidateGrantTypePermissions>()
                        .SetOrder(ValidateEndpointPermissions.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ValidateDeviceRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application is null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));
                    }

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
            /// Contains the logic responsible of rejecting device requests made by applications
            /// that haven't been granted the appropriate grant type permission.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateScopePermissions : IOpenIddictServerHandler<ValidateDeviceRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateScopePermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                public ValidateScopePermissions(IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceRequestContext>()
                        .AddFilter<RequireClientIdParameter>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .AddFilter<RequireScopePermissionsEnabled>()
                        .UseScopedHandler<ValidateScopePermissions>()
                        .SetOrder(ValidateGrantTypePermissions.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ValidateDeviceRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application is null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));
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
            /// Contains the logic responsible of extracting verification requests and invoking the corresponding event handlers.
            /// </summary>
            public class ExtractVerificationRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ExtractVerificationRequest(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .AddFilter<RequireVerificationRequest>()
                        .UseScopedHandler<ExtractVerificationRequest>()
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

                    var notification = new ExtractVerificationRequestContext(context.Transaction);
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
            /// Contains the logic responsible of validating verification requests and invoking the corresponding event handlers.
            /// </summary>
            public class ValidateVerificationRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ValidateVerificationRequest(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .AddFilter<RequireVerificationRequest>()
                        .UseScopedHandler<ValidateVerificationRequest>()
                        .SetOrder(ExtractVerificationRequest.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ProcessRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new ValidateVerificationRequestContext(context.Transaction);
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

                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6065));
                }
            }

            /// <summary>
            /// Contains the logic responsible of handling verification requests and invoking the corresponding event handlers.
            /// </summary>
            public class HandleVerificationRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public HandleVerificationRequest(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .AddFilter<RequireVerificationRequest>()
                        .UseScopedHandler<HandleVerificationRequest>()
                        .SetOrder(ValidateVerificationRequest.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ProcessRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new HandleVerificationRequestContext(context.Transaction);
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
            /// Contains the logic responsible of processing sign-in responses and invoking the corresponding event handlers.
            /// </summary>
            public class ApplyVerificationResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ApplyVerificationResponse(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .AddFilter<RequireVerificationRequest>()
                        .UseScopedHandler<ApplyVerificationResponse<TContext>>()
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

                    var notification = new ApplyVerificationResponseContext(context.Transaction);
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
            /// Contains the logic responsible of attaching the claims principal resolved from the user code.
            /// </summary>
            public class AttachUserCodePrincipal : IOpenIddictServerHandler<HandleVerificationRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public AttachUserCodePrincipal(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleVerificationRequestContext>()
                        .UseScopedHandler<AttachUserCodePrincipal>()
                        .SetOrder(int.MinValue + 100_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(HandleVerificationRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Note: the user_code may not be present (e.g when the user typed
                    // the verification_uri manually without the user code appended).
                    // In this case, ignore the missing token so that a view can be
                    // rendered by the application to ask the user to enter the code.
                    if (string.IsNullOrEmpty(context.Request.UserCode))
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
                        // Note: authentication errors are deliberately not flowed up to the parent context.
                        return;
                    }

                    // Attach the security principal extracted from the token to the validation context.
                    context.Principal = notification.UserCodePrincipal;
                }
            }
        }
    }
}
