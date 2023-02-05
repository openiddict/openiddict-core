/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    public static class Session
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Logout request top-level processing:
             */
            ExtractLogoutRequest.Descriptor,
            ValidateLogoutRequest.Descriptor,
            HandleLogoutRequest.Descriptor,
            ApplyLogoutResponse<ProcessErrorContext>.Descriptor,
            ApplyLogoutResponse<ProcessRequestContext>.Descriptor,
            ApplyLogoutResponse<ProcessSignOutContext>.Descriptor,

            /*
             * Logout request validation:
             */
            ValidatePostLogoutRedirectUriParameter.Descriptor,
            ValidateClientId.Descriptor,
            ValidateClientPostLogoutRedirectUri.Descriptor,
            ValidateEndpointPermissions.Descriptor,
            ValidateToken.Descriptor,
            ValidateAuthorizedParty.Descriptor,

            /*
             * Logout request handling:
             */
            AttachPrincipal.Descriptor,

            /*
             * Logout response processing:
             */
            AttachPostLogoutRedirectUri.Descriptor,
            AttachResponseState.Descriptor);

        /// <summary>
        /// Contains the logic responsible for extracting logout requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractLogoutRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractLogoutRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireLogoutRequest>()
                    .UseScopedHandler<ExtractLogoutRequest>()
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

                var notification = new ExtractLogoutRequestContext(context.Transaction);
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
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0050));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6124), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating logout requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateLogoutRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateLogoutRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireLogoutRequest>()
                    .UseScopedHandler<ValidateLogoutRequest>()
                    .SetOrder(ExtractLogoutRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ValidateLogoutRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by handlers
                // that want to access the redirect_uri without triggering a new validation process.
                context.Transaction.SetProperty(typeof(ValidateLogoutRequestContext).FullName!, notification);

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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6125));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling logout requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleLogoutRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleLogoutRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireLogoutRequest>()
                    .UseScopedHandler<HandleLogoutRequest>()
                    .SetOrder(ValidateLogoutRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new HandleLogoutRequestContext(context.Transaction);
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

                if (notification.IsSignOutTriggered)
                {
                    var @event = new ProcessSignOutContext(context.Transaction)
                    {
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0051));
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing sign-in responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyLogoutResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyLogoutResponse(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireLogoutRequest>()
                    .UseScopedHandler<ApplyLogoutResponse<TContext>>()
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

                var notification = new ApplyLogoutResponseContext(context.Transaction);
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0052));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting logout requests that specify an invalid post_logout_redirect_uri parameter.
        /// </summary>
        public sealed class ValidatePostLogoutRedirectUriParameter : IOpenIddictServerHandler<ValidateLogoutRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateLogoutRequestContext>()
                    .UseSingletonHandler<ValidatePostLogoutRedirectUriParameter>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateLogoutRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (string.IsNullOrEmpty(context.PostLogoutRedirectUri))
                {
                    return default;
                }

                // If an optional post_logout_redirect_uri was provided, validate it.
                if (!Uri.TryCreate(context.PostLogoutRedirectUri, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6126), Parameters.PostLogoutRedirectUri, context.PostLogoutRedirectUri);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2030(Parameters.PostLogoutRedirectUri),
                        uri: SR.FormatID8000(SR.ID2030));

                    return default;
                }

                if (!string.IsNullOrEmpty(uri.Fragment))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6127), Parameters.PostLogoutRedirectUri, context.PostLogoutRedirectUri);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2031(Parameters.PostLogoutRedirectUri),
                        uri: SR.FormatID8000(SR.ID2031));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting logout requests
        /// that use an invalid client_id, if one was explicitly specified.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateClientId : IOpenIddictServerHandler<ValidateLogoutRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientId() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientId(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateLogoutRequestContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateClientId>()
                    .SetOrder(ValidatePostLogoutRedirectUriParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateLogoutRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: support for the client_id parameter was only added in the second draft of the
                // https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout specification
                // and is optional. As such, the client identifier is only validated if it was specified.
                if (string.IsNullOrEmpty(context.ClientId))
                {
                    return;
                }

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                if (application is null)
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6196), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2052(Parameters.ClientId),
                        uri: SR.FormatID8000(SR.ID2052));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting logout
        /// requests that use an invalid post_logout_redirect_uri.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateClientPostLogoutRedirectUri : IOpenIddictServerHandler<ValidateLogoutRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientPostLogoutRedirectUri() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientPostLogoutRedirectUri(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateLogoutRequestContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequirePostLogoutRedirectUriParameter>()
                    .UseScopedHandler<ValidateClientPostLogoutRedirectUri>()
                    .SetOrder(ValidateClientId.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateLogoutRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.PostLogoutRedirectUri), SR.FormatID4000(Parameters.PostLogoutRedirectUri));

                // Note: support for the client_id parameter was only added in the second draft of the
                // https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout specification
                // and is optional. To support all client stacks, this handler supports two scenarios:
                //
                //   * The client_id parameter is supported by the client and was explicitly sent:
                //     in this case, the post_logout_redirect_uris allowed for this client application
                //     are retrieved from the database: if one of them matches the specified URI,
                //     the request is considered valid. Otherwise, it's automatically rejected.
                //
                //   * The client_id parameter is not supported by the client or was not explicitly sent:
                //     in this case, all the applications matching the specified post_logout_redirect_uri
                //     are retrieved from the database: if one of them has been granted the correct endpoint
                //     permission, the request is considered valid. Otherwise, it's automatically rejected.
                //
                // Since the first method is more efficient, it's always used if a client_is was specified.

                if (!string.IsNullOrEmpty(context.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                    if (!await _applicationManager.ValidatePostLogoutRedirectUriAsync(application, context.PostLogoutRedirectUri))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6128), context.PostLogoutRedirectUri);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2052(Parameters.PostLogoutRedirectUri),
                            uri: SR.FormatID8000(SR.ID2052));

                        return;
                    }

                    return;
                }

                if (!await ValidatePostLogoutRedirectUriAsync(context.PostLogoutRedirectUri))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6128), context.PostLogoutRedirectUri);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2052(Parameters.PostLogoutRedirectUri),
                        uri: SR.FormatID8000(SR.ID2052));

                    return;
                }

                async ValueTask<bool> ValidatePostLogoutRedirectUriAsync([StringSyntax(StringSyntaxAttribute.Uri)] string uri)
                {
                    // To be considered valid, a post_logout_redirect_uri must correspond to an existing client application
                    // that was granted the ept:logout permission, unless endpoint permissions checking was explicitly disabled.

                    await foreach (var application in _applicationManager.FindByPostLogoutRedirectUriAsync(uri))
                    {
                        if (context.Options.IgnoreEndpointPermissions ||
                            await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.Logout))
                        {
                            return true;
                        }
                    }

                    return false;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting logout requests made by unauthorized applications.
        /// Note: this handler is not used when the degraded mode is enabled or when endpoint permissions are disabled.
        /// </summary>
        public sealed class ValidateEndpointPermissions : IOpenIddictServerHandler<ValidateLogoutRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateEndpointPermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateEndpointPermissions(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateLogoutRequestContext>()
                    .AddFilter<RequireEndpointPermissionsEnabled>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateEndpointPermissions>()
                    .SetOrder(ValidateClientPostLogoutRedirectUri.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateLogoutRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: support for the client_id parameter was only added in the second draft of the
                // https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout specification
                // and is optional. As such, the client permissions are only validated if it was specified.
                // If only post_logout_redirect_uri was specified, client permissions are expected to be
                // enforced by the ValidateClientPostLogoutRedirectUri handler when finding matching clients.
                if (string.IsNullOrEmpty(context.ClientId))
                {
                    return;
                }

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // Reject the request if the application is not allowed to use the logout endpoint.
                if (!await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.Logout))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6048), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2140),
                        uri: SR.FormatID8000(SR.ID2140));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the token(s) present in the request.
        /// </summary>
        public sealed class ValidateToken : IOpenIddictServerHandler<ValidateLogoutRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateToken(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateLogoutRequestContext>()
                    .UseScopedHandler<ValidateToken>()
                    .SetOrder(ValidateEndpointPermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateLogoutRequestContext context)
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
                context.IdentityTokenHintPrincipal = notification.IdentityTokenPrincipal;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting logout requests that specify an identity
        /// token hint that cannot be used by the client application sending the logout request.
        /// </summary>
        public sealed class ValidateAuthorizedParty : IOpenIddictServerHandler<ValidateLogoutRequestContext>
        {
            private readonly IOpenIddictApplicationManager? _applicationManager;

            public ValidateAuthorizedParty(IOpenIddictApplicationManager? applicationManager = null)
                => _applicationManager = applicationManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateLogoutRequestContext>()
                    .UseScopedHandler<ValidateAuthorizedParty>(static provider =>
                    {
                        // Note: the application manager is only resolved if the degraded mode was not enabled to ensure
                        // invalid core configuration exceptions are not thrown even if the managers were registered.
                        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

                        return options.EnableDegradedMode ?
                            new ValidateAuthorizedParty() :
                            new ValidateAuthorizedParty(provider.GetService<IOpenIddictApplicationManager>() ??
                                throw new InvalidOperationException(SR.GetResourceString(SR.ID0016)));
                    })
                    .SetOrder(ValidateToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateLogoutRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.IdentityTokenHintPrincipal is null)
                {
                    return;
                }

                // This handler is responsible for ensuring that the specified identity token hint
                // was issued to the same client that the one corresponding to the specified client_id
                // or inferred from post_logout_redirect_uri. To achieve that, two approaches are used:
                //
                //   * If an explicit client_id was received, the client_id is directly used to determine
                //     whether the specified id_token_hint lists it as an audience or as a presenter.
                //
                //   * If no explicit client_id was set, all the client applications for which a matching
                //     post_logout_redirect_uri exists are iterated to determine whether the specified
                //     id_token_hint principal lists one of them as a valid audience or presenter.
                //
                // Since the first method is more efficient, it's always used if a client_is was specified.

                if (!string.IsNullOrEmpty(context.ClientId))
                {
                    // If an explicit client_id was specified, it must be listed either as
                    // an audience or as a presenter for the request to be considered valid.
                    if (!context.IdentityTokenHintPrincipal.HasAudience(context.ClientId) &&
                        !context.IdentityTokenHintPrincipal.HasPresenter(context.ClientId))
                    {
                        context.Logger.LogWarning(SR.GetResourceString(SR.ID6198));

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.GetResourceString(SR.ID2141),
                            uri: SR.FormatID8000(SR.ID2141));

                        return;
                    }

                    return;
                }

                if (!context.Options.EnableDegradedMode && !string.IsNullOrEmpty(context.PostLogoutRedirectUri))
                {
                    if (_applicationManager is null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));
                    }

                    if (!await ValidateAuthorizedParty(context.IdentityTokenHintPrincipal, context.PostLogoutRedirectUri))
                    {
                        context.Logger.LogWarning(SR.GetResourceString(SR.ID6198));

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.GetResourceString(SR.ID2141),
                            uri: SR.FormatID8000(SR.ID2141));

                        return;
                    }

                    return;
                }

                async ValueTask<bool> ValidateAuthorizedParty(ClaimsPrincipal principal,
                    [StringSyntax(StringSyntaxAttribute.Uri)] string uri)
                {
                    // To be considered valid, one of the clients matching the specified post_logout_redirect_uri
                    // must be listed either as an audience or as a presenter in the identity token hint.

                    await foreach (var application in _applicationManager.FindByPostLogoutRedirectUriAsync(uri))
                    {
                        var identifier = await _applicationManager.GetClientIdAsync(application);
                        if (!string.IsNullOrEmpty(identifier) && (principal.HasAudience(identifier) ||
                                                                  principal.HasPresenter(identifier)))
                        {
                            return true;
                        }
                    }

                    return false;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the principal
        /// extracted from the identity token hint to the event context.
        /// </summary>
        public sealed class AttachPrincipal : IOpenIddictServerHandler<HandleLogoutRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleLogoutRequestContext>()
                    .UseSingletonHandler<AttachPrincipal>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleLogoutRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = context.Transaction.GetProperty<ValidateLogoutRequestContext>(
                    typeof(ValidateLogoutRequestContext).FullName!) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

                context.IdentityTokenHintPrincipal ??= notification.IdentityTokenHintPrincipal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for inferring the redirect URI
        /// used to send the response back to the client application.
        /// </summary>
        public sealed class AttachPostLogoutRedirectUri : IOpenIddictServerHandler<ApplyLogoutResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyLogoutResponseContext>()
                    .UseSingletonHandler<AttachPostLogoutRedirectUri>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyLogoutResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Request is null)
                {
                    return default;
                }

                var notification = context.Transaction.GetProperty<ValidateLogoutRequestContext>(
                    typeof(ValidateLogoutRequestContext).FullName!);

                // Note: at this stage, the validated redirect URI property may be null (e.g if
                // an error is returned from the ExtractLogoutRequest/ValidateLogoutRequest events).
                if (notification is { IsRejected: false })
                {
                    context.PostLogoutRedirectUri = notification.PostLogoutRedirectUri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the state to the response.
        /// </summary>
        public sealed class AttachResponseState : IOpenIddictServerHandler<ApplyLogoutResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyLogoutResponseContext>()
                    .UseSingletonHandler<AttachResponseState>()
                    .SetOrder(AttachPostLogoutRedirectUri.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyLogoutResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Attach the request state to the logout response.
                if (string.IsNullOrEmpty(context.Response.State))
                {
                    context.Response.State = context.Request?.State;
                }

                return default;
            }
        }
    }
}
