/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;

namespace OpenIddict.Server
{
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
                ValidateCodeChallengeParameters.Descriptor,
                ValidateClientId.Descriptor,
                ValidateClientType.Descriptor,
                ValidateClientRedirectUri.Descriptor,
                ValidateScopes.Descriptor,
                ValidateEndpointPermissions.Descriptor,
                ValidateGrantTypePermissions.Descriptor,
                ValidateScopePermissions.Descriptor,
                ValidateProofKeyForCodeExchangeRequirement.Descriptor,

                /*
                 * Authorization response processing:
                 */
                AttachRedirectUri.Descriptor,
                InferResponseMode.Descriptor,
                AttachResponseState.Descriptor);

            /// <summary>
            /// Contains the logic responsible of extracting authorization requests and invoking the corresponding event handlers.
            /// </summary>
            public class ExtractAuthorizationRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ExtractAuthorizationRequest([NotNull] IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
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

                    if (notification.Request == null)
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("The authorization request was not correctly extracted. To extract authorization requests, ")
                            .Append("create a class implementing 'IOpenIddictServerHandler<ExtractAuthorizationRequestContext>' ")
                            .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                            .ToString());
                    }

                    context.Logger.LogInformation("The authorization request was successfully extracted: {Request}.", notification.Request);
                }
            }

            /// <summary>
            /// Contains the logic responsible of validating authorization requests and invoking the corresponding event handlers.
            /// </summary>
            public class ValidateAuthorizationRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ValidateAuthorizationRequest([NotNull] IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new ValidateAuthorizationRequestContext(context.Transaction);
                    await _dispatcher.DispatchAsync(notification);

                    // Store the context object in the transaction so it can be later retrieved by handlers
                    // that want to access the redirect_uri without triggering a new validation process.
                    context.Transaction.SetProperty(typeof(ValidateAuthorizationRequestContext).FullName, notification);

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
                        throw new InvalidOperationException("The request cannot be validated because no redirect_uri was specified.");
                    }

                    context.Logger.LogInformation("The authorization request was successfully validated.");
                }
            }

            /// <summary>
            /// Contains the logic responsible of handling authorization requests and invoking the corresponding event handlers.
            /// </summary>
            public class HandleAuthorizationRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public HandleAuthorizationRequest([NotNull] IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
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

                    if (notification.Principal != null)
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
                                error: @event.Error ?? Errors.InvalidRequest,
                                description: @event.ErrorDescription,
                                uri: @event.ErrorUri);
                            return;
                        }
                    }

                    throw new InvalidOperationException(new StringBuilder()
                        .Append("The authorization request was not handled. To handle authorization requests in a controller, ")
                        .Append("create a custom controller action with the same route as the authorization endpoint ")
                        .Append("and enable the pass-through mode in the server ASP.NET Core or OWIN options using ")
                        .AppendLine("'services.AddOpenIddict().AddServer().UseAspNetCore().EnableAuthorizationEndpointPassthrough()'.")
                        .Append("Alternatively, create a class implementing 'IOpenIddictServerHandler<HandleAuthorizationRequestContext>' ")
                        .Append("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                        .ToString());
                }
            }

            /// <summary>
            /// Contains the logic responsible of processing sign-in responses and invoking the corresponding event handlers.
            /// </summary>
            public class ApplyAuthorizationResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ApplyAuthorizationResponse([NotNull] IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] TContext context)
                {
                    if (context == null)
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

                    throw new InvalidOperationException(new StringBuilder()
                        .Append("The authorization response was not correctly applied. To apply authorization responses, ")
                        .Append("create a class implementing 'IOpenIddictServerHandler<ApplyAuthorizationResponseContext>' ")
                        .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                        .ToString());
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests that specify the unsupported request parameter.
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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Reject requests using the unsupported request parameter.
                    if (!string.IsNullOrEmpty(context.Request.Request))
                    {
                        context.Logger.LogError("The authorization request was rejected because it contained " +
                                                "an unsupported parameter: {Parameter}.", "request");

                        context.Reject(
                            error: Errors.RequestNotSupported,
                            description: "The 'request' parameter is not supported.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests that specify the unsupported request_uri parameter.
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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Reject requests using the unsupported request_uri parameter.
                    if (!string.IsNullOrEmpty(context.Request.RequestUri))
                    {
                        context.Logger.LogError("The authorization request was rejected because it contained " +
                                                "an unsupported parameter: {Parameter}.", "request_uri");

                        context.Reject(
                            error: Errors.RequestUriNotSupported,
                            description: "The 'request_uri' parameter is not supported.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests that lack the mandatory client_id parameter.
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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // client_id is a required parameter and MUST cause an error when missing.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
                    if (string.IsNullOrEmpty(context.ClientId))
                    {
                        context.Logger.LogError("The authorization request was rejected because " +
                                                "the mandatory 'client_id' parameter was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'client_id' parameter is missing.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests that lack the mandatory redirect_uri parameter.
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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
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
                            context.Logger.LogError("The authorization request was rejected because " +
                                                    "the mandatory 'redirect_uri' parameter was missing.");

                            context.Reject(
                                error: Errors.InvalidRequest,
                                description: "The mandatory 'redirect_uri' parameter is missing.");

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
                    if (!Uri.TryCreate(context.RedirectUri, UriKind.Absolute, out Uri uri) || !uri.IsWellFormedOriginalString())
                    {
                        context.Logger.LogError("The authorization request was rejected because the 'redirect_uri' parameter " +
                                                "didn't correspond to a valid absolute URL: {RedirectUri}.", context.RedirectUri);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The 'redirect_uri' parameter must be a valid absolute URL.");

                        return default;
                    }

                    // Note: when specified, redirect_uri MUST NOT include a fragment component.
                    // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                    // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                    if (!string.IsNullOrEmpty(uri.Fragment))
                    {
                        context.Logger.LogError("The authorization request was rejected because the 'redirect_uri' " +
                                                "contained a URL fragment: {RedirectUri}.", context.RedirectUri);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The 'redirect_uri' parameter must not include a fragment.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests that specify an invalid response_type parameter.
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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Reject requests missing the mandatory response_type parameter.
                    if (string.IsNullOrEmpty(context.Request.ResponseType))
                    {
                        context.Logger.LogError("The authorization request was rejected because " +
                                                "the mandatory 'response_type' parameter was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'response_type' parameter is missing.");

                        return default;
                    }

                    // Reject requests that specify an unsupported response_type.
                    var types = new HashSet<string>(context.Request.GetResponseTypes(), StringComparer.Ordinal);
                    if (!context.Options.ResponseTypes.Any(type =>
                        types.SetEquals(type.Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries))))
                    {
                        context.Logger.LogError("The authorization request was rejected because the '{ResponseType}' " +
                                                "response type is not supported.", context.Request.ResponseType);

                        context.Reject(
                            error: Errors.UnsupportedResponseType,
                            description: "The specified 'response_type' parameter is not allowed.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests that specify an invalid response_mode parameter.
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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // response_mode=query (explicit or not) and a response_type containing id_token
                    // or token are not considered as a safe combination and MUST be rejected.
                    // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Security.
                    if (context.Request.IsQueryResponseMode() && (context.Request.HasResponseType(ResponseTypes.IdToken) ||
                                                                  context.Request.HasResponseType(ResponseTypes.Token)))
                    {
                        context.Logger.LogError("The authorization request was rejected because the 'response_type'/'response_mode' " +
                                                "combination was invalid: {ResponseType} ; {ResponseMode}.",
                                                context.Request.ResponseType, context.Request.ResponseMode);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The specified 'response_type'/'response_mode' combination is invalid.");

                        return default;
                    }

                    // Reject requests that specify an unsupported response_mode or don't specify a different response_mode
                    // if the default response_mode inferred from the response_type was explicitly disabled in the options.
                    if (!ValidateResponseMode(context.Request, context.Options))
                    {
                        context.Logger.LogError("The authorization request was rejected because the '{ResponseMode}' " +
                                                "response mode is not supported.", context.Request.ResponseMode);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The specified 'response_mode' parameter is not supported.");

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
            /// Contains the logic responsible of rejecting authorization requests that don't specify a valid scope parameter.
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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Reject authorization requests containing the id_token response_type if no openid scope has been received.
                    if (context.Request.HasResponseType(ResponseTypes.IdToken) && !context.Request.HasScope(Scopes.OpenId))
                    {
                        context.Logger.LogError("The authorization request was rejected because the 'openid' scope was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'openid' scope is missing.");

                        return default;
                    }

                    // Reject authorization requests that specify scope=offline_access if the refresh token flow is not enabled.
                    if (context.Request.HasScope(Scopes.OfflineAccess) && !context.Options.GrantTypes.Contains(GrantTypes.RefreshToken))
                    {
                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The 'offline_access' scope is not allowed.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests that don't specify a nonce.
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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
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
                        context.Logger.LogError("The authorization request was rejected because the mandatory 'nonce' parameter was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'nonce' parameter is missing.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests that don't specify a valid prompt parameter.
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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Reject requests specifying prompt=none with consent/login or select_account.
                    if (context.Request.HasPrompt(Prompts.None) && (context.Request.HasPrompt(Prompts.Consent) ||
                                                                    context.Request.HasPrompt(Prompts.Login) ||
                                                                    context.Request.HasPrompt(Prompts.SelectAccount)))
                    {
                        context.Logger.LogError("The authorization request was rejected because an invalid prompt parameter was specified.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The specified 'prompt' parameter is invalid.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests that don't specify valid code challenge parameters.
            /// </summary>
            public class ValidateCodeChallengeParameters : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                        .UseSingletonHandler<ValidateCodeChallengeParameters>()
                        .SetOrder(ValidatePromptParameter.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (string.IsNullOrEmpty(context.Request.CodeChallenge) &&
                        string.IsNullOrEmpty(context.Request.CodeChallengeMethod))
                    {
                        return default;
                    }

                    // Ensure a code_challenge was specified if a code_challenge_method was used.
                    if (string.IsNullOrEmpty(context.Request.CodeChallenge))
                    {
                        context.Logger.LogError("The authorization request was rejected because the code_challenge was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The 'code_challenge_method' parameter cannot be used without 'code_challenge'.");

                        return default;
                    }

                    // If the plain code challenge method was not explicitly enabled,
                    // reject the request indicating that a method must be set.
                    if (string.IsNullOrEmpty(context.Request.CodeChallengeMethod) &&
                        !context.Options.CodeChallengeMethods.Contains(CodeChallengeMethods.Plain))
                    {
                        context.Logger.LogError("The authorization request was rejected because the " +
                                                "required 'code_challenge_method' parameter was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The 'code_challenge_method' parameter must be specified.");

                        return default;
                    }

                    // If a code_challenge_method was specified, ensure the algorithm is supported.
                    if (!string.IsNullOrEmpty(context.Request.CodeChallengeMethod) &&
                        !context.Options.CodeChallengeMethods.Contains(context.Request.CodeChallengeMethod))
                    {
                        context.Logger.LogError("The authorization request was rejected because " +
                                                "the specified code challenge method was not supported.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The specified 'code_challenge_method' parameter is not supported.");

                        return default;
                    }

                    // When code_challenge or code_challenge_method is specified, ensure the response_type includes "code".
                    if (!context.Request.HasResponseType(ResponseTypes.Code))
                    {
                        context.Logger.LogError("The authorization request was rejected because the response type " +
                                                "was not compatible with 'code_challenge'/'code_challenge_method'.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The 'code_challenge' and 'code_challenge_method' parameters " +
                                         "can only be used with a response type containing 'code'.");

                        return default;
                    }

                    // Reject authorization requests that contain response_type=token when a code_challenge is specified.
                    if (context.Request.HasResponseType(ResponseTypes.Token))
                    {
                        context.Logger.LogError("The authorization request was rejected because the " +
                                                "specified response type was not compatible with PKCE.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The specified 'response_type' parameter is not allowed when using PKCE.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests that use an invalid client_id.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientId : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientId() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateClientId([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .UseScopedHandler<ValidateClientId>()
                        .SetOrder(ValidateCodeChallengeParameters.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        context.Logger.LogError("The authorization request was rejected because the client " +
                                                "application was not found: '{ClientId}'.", context.ClientId);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The specified 'client_id' parameter is invalid.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests
            /// that use a response_type incompatible with the client application.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientType : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientType() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateClientType([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The client application details cannot be found in the database.");
                    }

                    // To prevent downgrade attacks, ensure that authorization requests returning an access token directly
                    // from the authorization endpoint are rejected if the client_id corresponds to a confidential application.
                    // Note: when using the authorization code grant, the ValidateClientSecret handler is responsible of rejecting
                    // the token request if the client_id corresponds to an unauthenticated confidential client.
                    if (context.Request.HasResponseType(ResponseTypes.Token) &&
                        await _applicationManager.HasClientTypeAsync(application, ClientTypes.Confidential))
                    {
                        context.Logger.LogError("The authorization request was rejected because the confidential application '{ClientId}' " +
                                                "was not allowed to retrieve an access token from the authorization endpoint.", context.ClientId);

                        context.Reject(
                            error: Errors.UnauthorizedClient,
                            description: "The specified 'response_type' parameter is not valid for this client application.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests that use an invalid redirect_uri.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateClientRedirectUri : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateClientRedirectUri() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateClientRedirectUri([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The client application details cannot be found in the database.");
                    }

                    // If no explicit redirect_uri was specified, retrieve the addresses associated with
                    // the client and ensure exactly one redirect_uri was attached to the client definition.
                    if (string.IsNullOrEmpty(context.RedirectUri))
                    {
                        var addresses = await _applicationManager.GetRedirectUrisAsync(application);
                        if (addresses.Length != 1)
                        {
                            context.Logger.LogError("The authorization request was rejected because " +
                                                    "the mandatory 'redirect_uri' parameter was missing.");

                            context.Reject(
                                error: Errors.InvalidRequest,
                                description: "The mandatory 'redirect_uri' parameter is missing.");

                            return;
                        }

                        context.SetRedirectUri(addresses[0]);

                        return;
                    }

                    // Otherwise, ensure that the specified redirect_uri is valid and is associated with the client application.
                    if (!await _applicationManager.ValidateRedirectUriAsync(application, context.RedirectUri))
                    {
                        context.Logger.LogError("The authorization request was rejected because the redirect_uri " +
                                                "was invalid: '{RedirectUri}'.", context.RedirectUri);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The specified 'redirect_uri' parameter is not valid for this client application.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests that use unregistered scopes.
            /// Note: this handler is not used when the degraded mode is enabled or when scope validation is disabled.
            /// </summary>
            public class ValidateScopes : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
            {
                private readonly IOpenIddictScopeManager _scopeManager;

                public ValidateScopes() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateScopes([NotNull] IOpenIddictScopeManager scopeManager)
                    => _scopeManager = scopeManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                        .AddFilter<RequireScopeValidationEnabled>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .UseScopedHandler<ValidateScopes>()
                        .SetOrder(ValidateClientRedirectUri.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // If all the specified scopes are registered in the options, avoid making a database lookup.
                    var scopes = new HashSet<string>(context.Request.GetScopes(), StringComparer.Ordinal);
                    scopes.ExceptWith(context.Options.Scopes);

                    if (scopes.Count != 0)
                    {
                        await foreach (var scope in _scopeManager.FindByNamesAsync(scopes.ToImmutableArray()))
                        {
                            scopes.Remove(await _scopeManager.GetNameAsync(scope));
                        }
                    }

                    // If at least one scope was not recognized, return an error.
                    if (scopes.Count != 0)
                    {
                        context.Logger.LogError("The authentication request was rejected because " +
                                                "invalid scopes were specified: {Scopes}.", scopes);

                        context.Reject(
                            error: Errors.InvalidScope,
                            description: "The specified 'scope' parameter is not valid.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests made by unauthorized applications.
            /// Note: this handler is not used when the degraded mode is enabled or when endpoint permissions are disabled.
            /// </summary>
            public class ValidateEndpointPermissions : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateEndpointPermissions() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateEndpointPermissions([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The client application details cannot be found in the database.");
                    }

                    // Reject the request if the application is not allowed to use the authorization endpoint.
                    if (!await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.Authorization))
                    {
                        context.Logger.LogError("The authorization request was rejected because the application '{ClientId}' " +
                                                "was not allowed to use the authorization endpoint.", context.ClientId);

                        context.Reject(
                            error: Errors.UnauthorizedClient,
                            description: "This client application is not allowed to use the authorization endpoint.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests made by unauthorized applications.
            /// Note: this handler is not used when the degraded mode is enabled or when grant type permissions are disabled.
            /// </summary>
            public class ValidateGrantTypePermissions : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateGrantTypePermissions() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateGrantTypePermissions([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The client application details cannot be found in the database.");
                    }

                    // Reject the request if the application is not allowed to use the authorization code flow.
                    if (context.Request.IsAuthorizationCodeFlow() &&
                        !await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.AuthorizationCode))
                    {
                        context.Logger.LogError("The authorization request was rejected because the application '{ClientId}' " +
                                                "was not allowed to use the authorization code flow.", context.ClientId);

                        context.Reject(
                            error: Errors.UnauthorizedClient,
                            description: "The client application is not allowed to use the authorization code flow.");

                        return;
                    }

                    // Reject the request if the application is not allowed to use the implicit flow.
                    if (context.Request.IsImplicitFlow() &&
                        !await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.Implicit))
                    {
                        context.Logger.LogError("The authorization request was rejected because the application '{ClientId}' " +
                                                "was not allowed to use the implicit flow.", context.ClientId);

                        context.Reject(
                            error: Errors.UnauthorizedClient,
                            description: "The client application is not allowed to use the implicit flow.");

                        return;
                    }

                    // Reject the request if the application is not allowed to use the authorization code/implicit flows.
                    if (context.Request.IsHybridFlow() &&
                       (!await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.AuthorizationCode) ||
                        !await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.Implicit)))
                    {
                        context.Logger.LogError("The authorization request was rejected because the application '{ClientId}' " +
                                                "was not allowed to use the hybrid flow.", context.ClientId);

                        context.Reject(
                            error: Errors.UnauthorizedClient,
                            description: "The client application is not allowed to use the hybrid flow.");

                        return;
                    }

                    // Reject the request if the offline_access scope was request and if
                    // the application is not allowed to use the refresh token grant type.
                    if (context.Request.HasScope(Scopes.OfflineAccess) &&
                       !await _applicationManager.HasPermissionAsync(application, Permissions.GrantTypes.RefreshToken))
                    {
                        context.Logger.LogError("The authorization request was rejected because the application '{ClientId}' " +
                                                "was not allowed to request the 'offline_access' scope.", context.ClientId);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The client application is not allowed to use the 'offline_access' scope.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests made by unauthorized applications.
            /// Note: this handler is not used when the degraded mode is enabled or when scope permissions are disabled.
            /// </summary>
            public class ValidateScopePermissions : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateScopePermissions() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateScopePermissions([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                        .AddFilter<RequireScopePermissionsEnabled>()
                        .AddFilter<RequireDegradedModeDisabled>()
                        .UseScopedHandler<ValidateScopePermissions>()
                        .SetOrder(ValidateGrantTypePermissions.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The client application details cannot be found in the database.");
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
                            context.Logger.LogError("The authorization request was rejected because the application '{ClientId}' " +
                                                    "was not allowed to use the scope {Scope}.", context.ClientId, scope);

                            context.Reject(
                                error: Errors.InvalidRequest,
                                description: "This client application is not allowed to use the specified scope.");

                            return;
                        }
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting authorization requests made by
            /// applications for which proof key for code exchange (PKCE) was enforced.
            /// Note: this handler is not used when the degraded mode is enabled.
            /// </summary>
            public class ValidateProofKeyForCodeExchangeRequirement : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
            {
                private readonly IOpenIddictApplicationManager _applicationManager;

                public ValidateProofKeyForCodeExchangeRequirement() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                    .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                    .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                    .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                    .ToString());

                public ValidateProofKeyForCodeExchangeRequirement([NotNull] IOpenIddictApplicationManager applicationManager)
                    => _applicationManager = applicationManager;

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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // If a code_challenge was provided, the request is always considered valid,
                    // whether the proof key for code exchange requirement is enforced or not.
                    if (!string.IsNullOrEmpty(context.Request.CodeChallenge))
                    {
                        return;
                    }

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The client application details cannot be found in the database.");
                    }

                    if (await _applicationManager.HasRequirementAsync(application, Requirements.Features.ProofKeyForCodeExchange))
                    {
                        context.Logger.LogError("The authorization request was rejected because the " +
                                                "required 'code_challenge' parameter was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'code_challenge' parameter is missing.");

                        return;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of inferring the redirect URL
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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ApplyAuthorizationResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.Request == null)
                    {
                        return default;
                    }

                    var notification = context.Transaction.GetProperty<ValidateAuthorizationRequestContext>(
                        typeof(ValidateAuthorizationRequestContext).FullName);

                    // Note: at this stage, the validated redirect URI property may be null (e.g if an error
                    // is returned from the ExtractAuthorizationRequest/ValidateAuthorizationRequest events).
                    if (notification != null && !notification.IsRejected)
                    {
                        context.RedirectUri = notification.RedirectUri;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of inferring the response mode
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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ApplyAuthorizationResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.Request == null)
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
            /// Contains the logic responsible of attaching the state to the response.
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

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ApplyAuthorizationResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Attach the request state to the authorization response.
                    if (string.IsNullOrEmpty(context.Response.State))
                    {
                        context.Response.State = context.Request?.State;
                    }

                    return default;
                }
            }
        }
    }
}
