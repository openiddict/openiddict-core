/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Extensions;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    public static class Authentication
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authorization request top-level processing:
             */
            ExtractAuthorizationRequest.Descriptor,
            ValidateAuthorizationRequest.Descriptor,
            HandleAuthorizationRequest.Descriptor,
            ApplyAuthorizationResponse<ProcessChallengeContext>.Descriptor,
            ApplyAuthorizationResponse<ProcessErrorContext>.Descriptor,
            ApplyAuthorizationResponse<ProcessRequestContext>.Descriptor,
            ApplyAuthorizationResponse<ProcessSignInContext>.Descriptor,

            /*
             * Authorization request validation:
             */
            ValidateRequestParameter.Descriptor,
            ValidateRequestUriParameter.Descriptor,
            ValidateClientIdParameter.Descriptor,
            ValidateRedirectUriParameter.Descriptor,
            ValidateResponseTypeParameter.Descriptor,
            ValidateResponseModeParameter.Descriptor,
            ValidateScopeParameter.Descriptor,
            ValidateNonceParameter.Descriptor,
            ValidatePromptParameter.Descriptor,
            ValidateProofKeyForCodeExchangeParameters.Descriptor,
            ValidateClientId.Descriptor,
            ValidateClientType.Descriptor,
            ValidateClientRedirectUri.Descriptor,
            ValidateScopes.Descriptor,
            ValidateEndpointPermissions.Descriptor,
            ValidateGrantTypePermissions.Descriptor,
            ValidateResponseTypePermissions.Descriptor,
            ValidateScopePermissions.Descriptor,
            ValidateProofKeyForCodeExchangeRequirement.Descriptor,
            ValidateToken.Descriptor,
            ValidateAuthorizedParty.Descriptor,

            /*
             * Authorization request handling:
             */
            AttachPrincipal.Descriptor,

            /*
             * Authorization response processing:
             */
            AttachRedirectUri.Descriptor,
            InferResponseMode.Descriptor,
            AttachResponseState.Descriptor,
            AttachIssuer.Descriptor);

        /// <summary>
        /// Contains the logic responsible for extracting authorization requests and invoking the corresponding event handlers.
        /// </summary>
        public class ExtractAuthorizationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractAuthorizationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireAuthorizationRequest>()
                    .UseScopedHandler<ExtractAuthorizationRequest>()
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

                var notification = new ExtractAuthorizationRequestContext(context.Transaction);
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
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0027));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6030), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating authorization requests and invoking the corresponding event handlers.
        /// </summary>
        public class ValidateAuthorizationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateAuthorizationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireAuthorizationRequest>()
                    .UseScopedHandler<ValidateAuthorizationRequest>()
                    .SetOrder(ExtractAuthorizationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ValidateAuthorizationRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by handlers
                // that want to access the redirect_uri without triggering a new validation process.
                context.Transaction.SetProperty(typeof(ValidateAuthorizationRequestContext).FullName!, notification);

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

                if (string.IsNullOrEmpty(notification.RedirectUri))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0028));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6031));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling authorization requests and invoking the corresponding event handlers.
        /// </summary>
        public class HandleAuthorizationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleAuthorizationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireAuthorizationRequest>()
                    .UseScopedHandler<HandleAuthorizationRequest>()
                    .SetOrder(ValidateAuthorizationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new HandleAuthorizationRequestContext(context.Transaction);
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
                            error: @event.Error ?? Errors.InvalidRequest,
                            description: @event.ErrorDescription,
                            uri: @event.ErrorUri);
                        return;
                    }
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0029));
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing sign-in responses and invoking the corresponding event handlers.
        /// </summary>
        public class ApplyAuthorizationResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyAuthorizationResponse(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireAuthorizationRequest>()
                    .UseScopedHandler<ApplyAuthorizationResponse<TContext>>()
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

                var notification = new ApplyAuthorizationResponseContext(context.Transaction);
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0030));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that specify the unsupported request parameter.
        /// </summary>
        public class ValidateRequestParameter : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .UseSingletonHandler<ValidateRequestParameter>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reject requests using the unsupported request parameter.
                if (!string.IsNullOrEmpty(context.Request.Request))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6032), Parameters.Request);

                    context.Reject(
                        error: Errors.RequestNotSupported,
                        description: SR.FormatID2028(Parameters.Request),
                        uri: SR.FormatID8000(SR.ID2028));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that specify the unsupported request_uri parameter.
        /// </summary>
        public class ValidateRequestUriParameter : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .UseSingletonHandler<ValidateRequestUriParameter>()
                    .SetOrder(ValidateRequestParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reject requests using the unsupported request_uri parameter.
                if (!string.IsNullOrEmpty(context.Request.RequestUri))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6032), Parameters.RequestUri);

                    context.Reject(
                        error: Errors.RequestUriNotSupported,
                        description: SR.FormatID2028(Parameters.RequestUri),
                        uri: SR.FormatID8000(SR.ID2028));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that lack the mandatory client_id parameter.
        /// </summary>
        public class ValidateClientIdParameter : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .UseSingletonHandler<ValidateClientIdParameter>()
                    .SetOrder(ValidateRequestUriParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // client_id is a required parameter and MUST cause an error when missing.
                // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
                if (string.IsNullOrEmpty(context.ClientId))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6033), Parameters.ClientId);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.ClientId),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that lack the mandatory redirect_uri parameter.
        /// </summary>
        public class ValidateRedirectUriParameter : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .UseSingletonHandler<ValidateRedirectUriParameter>()
                    .SetOrder(ValidateClientIdParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // While redirect_uri was not mandatory in OAuth 2.0, this parameter
                // is now declared as REQUIRED and MUST cause an error when missing.
                // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
                // To keep OpenIddict compatible with pure OAuth 2.0 clients, an error
                // is only returned if the request was made by an OpenID Connect client.
                if (string.IsNullOrEmpty(context.RedirectUri))
                {
                    if (context.Request.HasScope(Scopes.OpenId))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6033), Parameters.RedirectUri);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2029(Parameters.RedirectUri),
                            uri: SR.FormatID8000(SR.ID2029));

                        return default;
                    }

                    return default;
                }

                // Note: when specified, redirect_uri MUST be an absolute URI.
                // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
                //
                // Note: on Linux/macOS, "/path" URLs are treated as valid absolute file URLs.
                // To ensure relative redirect_uris are correctly rejected on these platforms,
                // an additional check using IsWellFormedOriginalString() is made here.
                // See https://github.com/dotnet/corefx/issues/22098 for more information.
                if (!Uri.TryCreate(context.RedirectUri, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6034), Parameters.RedirectUri, context.RedirectUri);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2030(Parameters.RedirectUri),
                        uri: SR.FormatID8000(SR.ID2030));

                    return default;
                }

                // Note: when specified, redirect_uri MUST NOT include a fragment component.
                // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                if (!string.IsNullOrEmpty(uri.Fragment))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6035), Parameters.RedirectUri, context.RedirectUri);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2031(Parameters.RedirectUri),
                        uri: SR.FormatID8000(SR.ID2031));

                    return default;
                }

                // To prevent issuer fixation attacks where a malicious client would specify an "iss" parameter
                // in the redirect_uri, ensure the query - if present - doesn't include an "iss" parameter.
                //
                // Note: while OAuth 2.0 parameters are case-sentitive, the following check deliberately
                // uses a case-insensitive comparison to ensure that all variations of "iss" are rejected.
                if (!string.IsNullOrEmpty(uri.Query))
                {
                    var parameters = OpenIddictHelpers.ParseQuery(uri.Query);
                    if (parameters.ContainsKey(Parameters.Iss))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6181), Parameters.RedirectUri, Parameters.Iss);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2135(Parameters.RedirectUri, Parameters.Iss),
                            uri: SR.FormatID8000(SR.ID2135));

                        return default;
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that specify an invalid response_type parameter.
        /// </summary>
        public class ValidateResponseTypeParameter : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .UseSingletonHandler<ValidateResponseTypeParameter>()
                    .SetOrder(ValidateRedirectUriParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reject requests missing the mandatory response_type parameter.
                if (string.IsNullOrEmpty(context.Request.ResponseType))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6033), Parameters.ResponseType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.ResponseType),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                // Reject code flow requests if the server is not configured to allow the authorization code grant type.
                if (context.Request.IsAuthorizationCodeFlow() && !context.Options.GrantTypes.Contains(GrantTypes.AuthorizationCode))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6036), context.Request.ResponseType);

                    context.Reject(
                        error: Errors.UnsupportedResponseType,
                        description: SR.FormatID2032(Parameters.ResponseType),
                        uri: SR.FormatID8000(SR.ID2032));

                    return default;
                }

                // Reject implicit flow requests if the server is not configured to allow the implicit grant type.
                if (context.Request.IsImplicitFlow() && !context.Options.GrantTypes.Contains(GrantTypes.Implicit))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6036), context.Request.ResponseType);

                    context.Reject(
                        error: Errors.UnsupportedResponseType,
                        description: SR.FormatID2032(Parameters.ResponseType),
                        uri: SR.FormatID8000(SR.ID2032));

                    return default;
                }

                // Reject hybrid flow requests if the server is not configured to allow the authorization code or implicit grant types.
                if (context.Request.IsHybridFlow() && (!context.Options.GrantTypes.Contains(GrantTypes.AuthorizationCode) ||
                                                       !context.Options.GrantTypes.Contains(GrantTypes.Implicit)))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6036), context.Request.ResponseType);

                    context.Reject(
                        error: Errors.UnsupportedResponseType,
                        description: SR.FormatID2032(Parameters.ResponseType),
                        uri: SR.FormatID8000(SR.ID2032));

                    return default;
                }

                // Reject requests that specify an unsupported response_type.
                var types = new HashSet<string>(context.Request.GetResponseTypes(), StringComparer.Ordinal);
                if (!context.Options.ResponseTypes.Any(type =>
                    types.SetEquals(type.Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries))))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6036), context.Request.ResponseType);

                    context.Reject(
                        error: Errors.UnsupportedResponseType,
                        description: SR.FormatID2032(Parameters.ResponseType),
                        uri: SR.FormatID8000(SR.ID2032));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that specify an invalid response_mode parameter.
        /// </summary>
        public class ValidateResponseModeParameter : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .UseSingletonHandler<ValidateResponseModeParameter>()
                    .SetOrder(ValidateResponseTypeParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // response_mode=query (explicit or not) and a response_type containing id_token
                // or token are not considered as a safe combination and MUST be rejected.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Security.
                if (context.Request.IsQueryResponseMode() && (context.Request.HasResponseType(ResponseTypes.IdToken) ||
                                                              context.Request.HasResponseType(ResponseTypes.Token)))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6037), context.Request.ResponseType, context.Request.ResponseMode);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2033(Parameters.ResponseType, Parameters.ResponseMode),
                        uri: SR.FormatID8000(SR.ID2033));

                    return default;
                }

                // Reject requests that specify an unsupported response_mode or don't specify a different response_mode
                // if the default response_mode inferred from the response_type was explicitly disabled in the options.
                if (!ValidateResponseMode(context.Request, context.Options))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6038), context.Request.ResponseMode);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2032(Parameters.ResponseMode),
                        uri: SR.FormatID8000(SR.ID2032));

                    return default;
                }

                return default;

                static bool ValidateResponseMode(OpenIddictRequest request, OpenIddictServerOptions options)
                {
                    // Note: both the fragment and query response modes are used as default response modes
                    // when using the implicit/hybrid and code flows if no explicit value was set.
                    // To ensure requests are rejected if the default response mode was manually disabled,
                    // the fragment and query response modes are checked first using the appropriate extensions.

                    if (request.IsFragmentResponseMode())
                    {
                        return options.ResponseModes.Contains(ResponseModes.Fragment);
                    }

                    if (request.IsQueryResponseMode())
                    {
                        return options.ResponseModes.Contains(ResponseModes.Query);
                    }

                    if (string.IsNullOrEmpty(request.ResponseMode))
                    {
                        return true;
                    }

                    return options.ResponseModes.Contains(request.ResponseMode);
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that don't specify a valid scope parameter.
        /// </summary>
        public class ValidateScopeParameter : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .UseSingletonHandler<ValidateScopeParameter>()
                    .SetOrder(ValidateResponseModeParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reject authorization requests containing the id_token response_type if no openid scope has been received.
                if (context.Request.HasResponseType(ResponseTypes.IdToken) && !context.Request.HasScope(Scopes.OpenId))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6039), Scopes.OpenId);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2034(Scopes.OpenId),
                        uri: SR.FormatID8000(SR.ID2034));

                    return default;
                }

                // Reject authorization requests that specify scope=offline_access if the refresh token flow is not enabled.
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
        /// Contains the logic responsible for rejecting authorization requests that don't specify a nonce.
        /// </summary>
        public class ValidateNonceParameter : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .UseSingletonHandler<ValidateNonceParameter>()
                    .SetOrder(ValidateScopeParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reject OpenID Connect implicit/hybrid requests missing the mandatory nonce parameter.
                // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest,
                // http://openid.net/specs/openid-connect-implicit-1_0.html#RequestParameters
                // and http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken.

                if (!string.IsNullOrEmpty(context.Request.Nonce) || !context.Request.HasScope(Scopes.OpenId))
                {
                    return default;
                }

                if (context.Request.IsImplicitFlow() || context.Request.IsHybridFlow())
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6033), Parameters.Nonce);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.Nonce),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that don't specify a valid prompt parameter.
        /// </summary>
        public class ValidatePromptParameter : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .UseSingletonHandler<ValidatePromptParameter>()
                    .SetOrder(ValidateNonceParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reject requests specifying prompt=none with consent/login or select_account.
                if (context.Request.HasPrompt(Prompts.None) && (context.Request.HasPrompt(Prompts.Consent) ||
                                                                context.Request.HasPrompt(Prompts.Login) ||
                                                                context.Request.HasPrompt(Prompts.SelectAccount)))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6040));

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2052(Parameters.Prompt),
                        uri: SR.FormatID8000(SR.ID2052));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that don't specify valid PKCE parameters.
        /// </summary>
        public class ValidateProofKeyForCodeExchangeParameters : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .UseSingletonHandler<ValidateProofKeyForCodeExchangeParameters>()
                    .SetOrder(ValidatePromptParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If OpenIddict was configured to require PKCE, reject the request if the code challenge
                // is missing and if an authorization code was requested by the client application.
                if (context.Options.RequireProofKeyForCodeExchange &&
                    context.Request.HasResponseType(ResponseTypes.Code) &&
                    string.IsNullOrEmpty(context.Request.CodeChallenge))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6033), Parameters.CodeChallenge);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.CodeChallenge),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                // At this point, stop validating the PKCE parameters if both the
                // code_challenge and code_challenge_method parameter are missing.
                if (string.IsNullOrEmpty(context.Request.CodeChallenge) &&
                    string.IsNullOrEmpty(context.Request.CodeChallengeMethod))
                {
                    return default;
                }

                // Ensure a code_challenge was specified if a code_challenge_method was used.
                if (string.IsNullOrEmpty(context.Request.CodeChallenge))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6033), Parameters.CodeChallenge);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2037(Parameters.CodeChallengeMethod, Parameters.CodeChallenge),
                        uri: SR.FormatID8000(SR.ID2037));

                    return default;
                }

                // If the plain code challenge method was not explicitly enabled,
                // reject the request indicating that a method must be set.
                if (string.IsNullOrEmpty(context.Request.CodeChallengeMethod) &&
                    !context.Options.CodeChallengeMethods.Contains(CodeChallengeMethods.Plain))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6033), Parameters.CodeChallengeMethod);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.CodeChallengeMethod),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                // If a code_challenge_method was specified, ensure the algorithm is supported.
                if (!string.IsNullOrEmpty(context.Request.CodeChallengeMethod) &&
                    !context.Options.CodeChallengeMethods.Contains(context.Request.CodeChallengeMethod))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6041));

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2032(Parameters.CodeChallengeMethod),
                        uri: SR.FormatID8000(SR.ID2032));

                    return default;
                }

                // When code_challenge or code_challenge_method is specified, ensure the response_type includes "code".
                if (!context.Request.HasResponseType(ResponseTypes.Code))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6042));

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2040(Parameters.CodeChallenge, Parameters.CodeChallengeMethod, ResponseTypes.Code),
                        uri: SR.FormatID8000(SR.ID2040));

                    return default;
                }

                // Reject authorization requests that contain response_type=token when a code_challenge is specified.
                if (context.Request.HasResponseType(ResponseTypes.Token))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6043));

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2041(Parameters.ResponseType),
                        uri: SR.FormatID8000(SR.ID2041));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that use an invalid client_id.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateClientId : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientId() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientId(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateClientId>()
                    .SetOrder(ValidateProofKeyForCodeExchangeParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                if (application is null)
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6044), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2052(Parameters.ClientId),
                        uri: SR.FormatID8000(SR.ID2052));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that use a
        /// response_type containing token if the application is a confidential client.
        /// Note: this handler is not used when the degraded mode is enabled
        /// or when response type permissions enforcement is not disabled.
        /// </summary>
        public class ValidateClientType : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientType() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientType(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateClientType>()
                    .SetOrder(ValidateClientId.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // To prevent downgrade attacks, ensure that authorization requests returning an access token directly
                // from the authorization endpoint are rejected if the client_id corresponds to a confidential application
                // and if response type permissions enforcement was explicitly disabled in the server options.
                // Users who want to enable this advanced scenario are encouraged to re-enable permissions validation.
                //
                // Alternatively, this handler can be removed from the handlers list using the events model APIs.
                if (!context.Options.IgnoreResponseTypePermissions || !context.Request.HasResponseType(ResponseTypes.Token))
                {
                    return;
                }

                if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Confidential))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6045), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.FormatID2043(Parameters.ResponseType),
                        uri: SR.FormatID8000(SR.ID2043));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that use an invalid redirect_uri.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateClientRedirectUri : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientRedirectUri() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientRedirectUri(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateClientRedirectUri>()
                    .SetOrder(ValidateClientType.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // If no explicit redirect_uri was specified, retrieve the addresses associated with
                // the client and ensure exactly one redirect_uri was attached to the client definition.
                if (string.IsNullOrEmpty(context.RedirectUri))
                {
                    var addresses = await _applicationManager.GetRedirectUrisAsync(application);
                    if (addresses.Length is not 1)
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6033), Parameters.RedirectUri);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2029(Parameters.RedirectUri),
                            uri: SR.FormatID8000(SR.ID2029));

                        return;
                    }

                    context.SetRedirectUri(addresses[0]);

                    return;
                }

                // Otherwise, ensure that the specified redirect_uri is valid and is associated with the client application.
                if (!await _applicationManager.ValidateRedirectUriAsync(application, context.RedirectUri))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6046), context.RedirectUri);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2043(Parameters.RedirectUri),
                        uri: SR.FormatID8000(SR.ID2043));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that use unregistered scopes.
        /// Note: this handler partially works with the degraded mode but is not used when scope validation is disabled.
        /// </summary>
        public class ValidateScopes : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            private readonly IOpenIddictScopeManager? _scopeManager;

            public ValidateScopes(IOpenIddictScopeManager? scopeManager = null)
                => _scopeManager = scopeManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
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
                    .SetOrder(ValidateClientRedirectUri.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
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
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6047), scopes);

                    context.Reject(
                        error: Errors.InvalidScope,
                        description: SR.FormatID2052(Parameters.Scope),
                        uri: SR.FormatID8000(SR.ID2052));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests made by unauthorized applications.
        /// Note: this handler is not used when the degraded mode is enabled or when endpoint permissions are disabled.
        /// </summary>
        public class ValidateEndpointPermissions : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateEndpointPermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateEndpointPermissions(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .AddFilter<RequireEndpointPermissionsEnabled>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateEndpointPermissions>()
                    .SetOrder(ValidateScopes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // Reject the request if the application is not allowed to use the authorization endpoint.
                if (!await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.Authorization))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6048), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2046),
                        uri: SR.FormatID8000(SR.ID2046));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests made by unauthorized applications.
        /// Note: this handler is not used when the degraded mode is enabled or when grant type permissions are disabled.
        /// </summary>
        public class ValidateGrantTypePermissions : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateGrantTypePermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateGrantTypePermissions(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .AddFilter<RequireGrantTypePermissionsEnabled>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateGrantTypePermissions>()
                    .SetOrder(ValidateEndpointPermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // Reject the request if the application is not allowed to use the authorization code grant.
                if (context.Request.IsAuthorizationCodeFlow() &&
                    !await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.AuthorizationCode))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6049), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2047),
                        uri: SR.FormatID8000(SR.ID2047));

                    return;
                }

                // Reject the request if the application is not allowed to use the implicit grant.
                if (context.Request.IsImplicitFlow() &&
                    !await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.Implicit))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6050), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2048),
                        uri: SR.FormatID8000(SR.ID2048));

                    return;
                }

                // Reject the request if the application is not allowed to use the authorization code/implicit grants.
                if (context.Request.IsHybridFlow() &&
                   (!await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.AuthorizationCode) ||
                    !await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.Implicit)))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6051), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2049),
                        uri: SR.FormatID8000(SR.ID2049));

                    return;
                }

                // Reject the request if the offline_access scope was request and
                // if the application is not allowed to use the refresh token grant.
                if (context.Request.HasScope(Scopes.OfflineAccess) &&
                   !await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.RefreshToken))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6052), context.ClientId, Scopes.OfflineAccess);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2065(Scopes.OfflineAccess),
                        uri: SR.FormatID8000(SR.ID2065));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests made by unauthorized applications.
        /// Note: this handler is not used when the degraded mode is enabled or when grant type permissions are disabled.
        /// </summary>
        public class ValidateResponseTypePermissions : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateResponseTypePermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateResponseTypePermissions(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .AddFilter<RequireResponseTypePermissionsEnabled>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateResponseTypePermissions>()
                    .SetOrder(ValidateGrantTypePermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // Reject requests that specify a response_type for which no permission was granted.
                if (!await HasPermissionAsync(context.Request.GetResponseTypes()))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6177), context.ClientId, context.Request.ResponseType);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.FormatID2043(Parameters.ResponseType),
                        uri: SR.FormatID8000(SR.ID2043));

                    return;
                }

                async ValueTask<bool> HasPermissionAsync(IEnumerable<string> types)
                {
                    // Note: response type permissions are always prefixed with "rst:".
                    const string prefix = Permissions.Prefixes.ResponseType;

                    foreach (var permission in await _applicationManager.GetPermissionsAsync(application))
                    {
                        // Ignore permissions that are not response type permissions.
                        if (!permission.StartsWith(prefix, StringComparison.Ordinal))
                        {
                            continue;
                        }

                        // Note: response types can be specified in any order. To ensure permissions are correctly
                        // checked even if the order differs from the one specified in the request, a HashSet is used.
                        var values = permission.Substring(prefix.Length, permission.Length - prefix.Length)
                                               .Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries);

                        if (values.Length is not 0 && new HashSet<string>(values, StringComparer.Ordinal).SetEquals(types))
                        {
                            return true;
                        }
                    }

                    return false;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests made by unauthorized applications.
        /// Note: this handler is not used when the degraded mode is enabled or when scope permissions are disabled.
        /// </summary>
        public class ValidateScopePermissions : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateScopePermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateScopePermissions(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .AddFilter<RequireScopePermissionsEnabled>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateScopePermissions>()
                    .SetOrder(ValidateResponseTypePermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
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
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6052), context.ClientId, scope);

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
        /// Contains the logic responsible for rejecting authorization requests made by
        /// applications for which proof key for code exchange (PKCE) was enforced.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateProofKeyForCodeExchangeRequirement : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateProofKeyForCodeExchangeRequirement() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateProofKeyForCodeExchangeRequirement(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseScopedHandler<ValidateProofKeyForCodeExchangeRequirement>()
                    .SetOrder(ValidateScopePermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                // If a code_challenge was provided or if no authorization code is requested, the request is always
                // considered valid, whether the proof key for code exchange requirement is enforced or not.
                if (!string.IsNullOrEmpty(context.Request.CodeChallenge) || !context.Request.HasResponseType(ResponseTypes.Code))
                {
                    return;
                }

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                if (await _applicationManager.HasRequirementAsync(application, Requirements.Features.ProofKeyForCodeExchange))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6033), Parameters.CodeChallenge);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2054(Parameters.CodeChallenge),
                        uri: SR.FormatID8000(SR.ID2054));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization
        /// requests that don't specify a valid id_token_hint.
        /// </summary>
        public class ValidateToken : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateToken(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .UseScopedHandler<ValidateToken>()
                    .SetOrder(ValidateProofKeyForCodeExchangeRequirement.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
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
        /// Contains the logic responsible for rejecting authorization requests that specify an identity
        /// token hint that cannot be used by the client application sending the authorization request.
        /// </summary>
        public class ValidateAuthorizedParty : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .UseSingletonHandler<ValidateAuthorizedParty>()
                    .SetOrder(ValidateToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.IdentityTokenHintPrincipal is null)
                {
                    return default;
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                // When an identity token hint is specified, the client_id (when present) must be
                // listed either as a valid audience or as a presenter to be considered valid.
                if (!context.IdentityTokenHintPrincipal.HasAudience(context.ClientId) &&
                    !context.IdentityTokenHintPrincipal.HasPresenter(context.ClientId))
                {
                    context.Logger.LogWarning(SR.GetResourceString(SR.ID6197));

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2141),
                        uri: SR.FormatID8000(SR.ID2141));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the principal
        /// extracted from the identity token hint to the event context.
        /// </summary>
        public class AttachPrincipal : IOpenIddictServerHandler<HandleAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleAuthorizationRequestContext>()
                    .UseSingletonHandler<AttachPrincipal>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = context.Transaction.GetProperty<ValidateAuthorizationRequestContext>(
                    typeof(ValidateAuthorizationRequestContext).FullName!) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

                context.IdentityTokenHintPrincipal ??= notification.IdentityTokenHintPrincipal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for inferring the redirect URL
        /// used to send the response back to the client application.
        /// </summary>
        public class AttachRedirectUri : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                    .UseSingletonHandler<AttachRedirectUri>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Request is null)
                {
                    return default;
                }

                var notification = context.Transaction.GetProperty<ValidateAuthorizationRequestContext>(
                    typeof(ValidateAuthorizationRequestContext).FullName!);

                // Note: at this stage, the validated redirect URI property may be null (e.g if an error
                // is returned from the ExtractAuthorizationRequest/ValidateAuthorizationRequest events).
                if (notification is { IsRejected: false })
                {
                    context.RedirectUri = notification.RedirectUri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for inferring the response mode
        /// used to send the response back to the client application.
        /// </summary>
        public class InferResponseMode : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                    .UseSingletonHandler<InferResponseMode>()
                    .SetOrder(AttachRedirectUri.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Request is null)
                {
                    return default;
                }

                context.ResponseMode = context.Request.ResponseMode;

                // If the response_mode parameter was not specified, try to infer it.
                if (string.IsNullOrEmpty(context.ResponseMode) && !string.IsNullOrEmpty(context.RedirectUri))
                {
                    context.ResponseMode = context.Request.IsFormPostResponseMode() ? ResponseModes.FormPost :
                                           context.Request.IsFragmentResponseMode() ? ResponseModes.Fragment :
                                           context.Request.IsQueryResponseMode()    ? ResponseModes.Query    : null;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the state to the response.
        /// </summary>
        public class AttachResponseState : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                    .UseSingletonHandler<AttachResponseState>()
                    .SetOrder(InferResponseMode.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If the user agent is expected to be redirected to the client application, attach the request
                // state to the authorization response to help the client mitigate CSRF/session fixation attacks.
                //
                // Note: don't override the state if one was already attached to the response instance.
                if (!string.IsNullOrEmpty(context.RedirectUri) && string.IsNullOrEmpty(context.Response.State))
                {
                    context.Response.State = context.Request?.State;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching an "iss" parameter
        /// containing the address of the authorization server to the response.
        /// </summary>
        public class AttachIssuer : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                    .UseSingletonHandler<AttachIssuer>()
                    .SetOrder(AttachResponseState.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If the user agent is expected to be redirected to the client application, attach the
                // issuer address to the authorization response to help the client detect mix-up attacks.
                //
                // Note: this applies to all authorization responses, whether they represent valid or errored responses.
                // For more information, see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-iss-auth-resp-05.

                if (!string.IsNullOrEmpty(context.RedirectUri))
                {
                    // At this stage, throw an exception if the issuer cannot be retrieved.
                    if (context.Issuer is not { IsAbsoluteUri: true })
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0023));
                    }

                    // Note: don't override the issuer if one was already attached to the response instance.
                    if (string.IsNullOrEmpty(context.Response.Iss))
                    {
                        context.Response.Iss = context.Issuer.AbsoluteUri;
                    }
                }

                return default;
            }
        }
    }
}
