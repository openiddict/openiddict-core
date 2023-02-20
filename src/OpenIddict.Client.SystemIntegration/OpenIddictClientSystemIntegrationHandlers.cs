/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Security.Claims;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using OpenIddict.Extensions;
using static OpenIddict.Client.SystemIntegration.OpenIddictClientSystemIntegrationConstants;

#if !SUPPORTS_HOST_APPLICATION_LIFETIME
using IHostApplicationLifetime = Microsoft.Extensions.Hosting.IApplicationLifetime;
#endif

#if SUPPORTS_WINDOWS_RUNTIME
using Windows.Security.Authentication.Web;
#endif

namespace OpenIddict.Client.SystemIntegration;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictClientSystemIntegrationHandlers
{
    public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
        /*
         * Top-level request processing:
         */
        ResolveRequestUriFromHttpListenerRequest.Descriptor,
        ResolveRequestUriFromProtocolActivation.Descriptor,
        ResolveRequestUriFromWebAuthenticationResult.Descriptor,
        InferEndpointTypeFromDynamicAddress.Descriptor,
        RejectUnknownHttpRequests.Descriptor,

        /*
         * Authentication processing:
         */
        WaitMarshalledAuthentication.Descriptor,
        RestoreStateTokenFromMarshalledAuthentication.Descriptor,
        RestoreStateTokenPrincipalFromMarshalledAuthentication.Descriptor,
        RestoreClientRegistrationFromMarshalledContext.Descriptor,
        RedirectProtocolActivation.Descriptor,
        ResolveRequestForgeryProtection.Descriptor,
        RestoreFrontchannelTokensFromMarshalledAuthentication.Descriptor,
        RestoreFrontchannelIdentityTokenPrincipalFromMarshalledAuthentication.Descriptor,
        RestoreFrontchannelAccessTokenPrincipalFromMarshalledAuthentication.Descriptor,
        RestoreAuthorizationCodePrincipalFromMarshalledAuthentication.Descriptor,
        RestoreBackchannelTokensFromMarshalledAuthentication.Descriptor,
        RestoreBackchannelIdentityTokenPrincipalFromMarshalledAuthentication.Descriptor,
        RestoreBackchannelAccessTokenPrincipalFromMarshalledAuthentication.Descriptor,
        RestoreRefreshTokenPrincipalFromMarshalledAuthentication.Descriptor,
        RestoreUserinfoDetailsFromMarshalledAuthentication.Descriptor,
        CompleteAuthenticationOperation.Descriptor,
        UntrackMarshalledAuthenticationOperation.Descriptor,

        /*
         * Challenge processing:
         */
        InferBaseUriFromClientUri.Descriptor,
        AttachDynamicPortToRedirectUri.Descriptor,
        AttachInstanceIdentifier.Descriptor,
        TrackAuthenticationOperation.Descriptor,

        /*
         * Error processing:
         */
        AbortAuthenticationDemand.Descriptor)
        .AddRange(Authentication.DefaultHandlers);

    /// <summary>
    /// Contains the logic responsible for resolving the request URI from the HTTP listener request.
    /// Note: this handler is not used when the OpenID Connect request is not handled by the embedded web server.
    /// </summary>
    public sealed class ResolveRequestUriFromHttpListenerRequest : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireHttpListenerContext>()
                .UseSingletonHandler<ResolveRequestUriFromHttpListenerRequest>()
                .SetOrder(int.MinValue + 50_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // When using the OpenIddict client system integration, requests can originate from multiple sources:
            //
            //   - A proper HTTP GET request handled by the embedded web server, when the authorization server
            //     returns an HTTP 302 response pointing to the local machine (e.g an authorization response).
            //     In this case, the handling is very similar to what's performed by the web-based OWIN or
            //     ASP.NET Core hosts and a proper HTTP response can be returned and rendered by the browser.
            //
            //   - A protocol activation triggered when the authorization server returns a HTTP 302 response
            //     with a redirection address associated with the client application (e.g using a manifest
            //     or a registry entry). In this case, the redirection is handled by the operating system
            //     that instantiates the application process and no response can be returned to the browser.
            //
            //   - A protocol activation redirected by another instance of the application using inter-process
            //     communication. The handling of such activations is similar to direct protocol activations
            //     and no response can be returned to the browser (that typically stays on the same page).
            //
            //   - A redirection handled transparently by a web-view component (e.g the web authentication
            //     broker on Windows). In this case, the modal window created by the application or the
            //     operating system is automatically closed when the specified callback URI is reached
            //     and there is no way to return a response that would be visible by the user.
            //
            // OpenIddict unifies these request models by sharing the same request processing pipeline and
            // by adapting the logic based on the request type (e.g only protocol activations are redirected
            // to other instances and can result in the current instance being terminated by OpenIddict).

            (context.BaseUri, context.RequestUri) = context.Transaction.GetHttpListenerContext() switch
            {
                // Note: unlike the equivalent handler in the ASP.NET Core and OWIN hosts, the URI is
                // expected to be always present and absolute, as the embedded web server is configured
                // to use "localhost" as the registered prefix, which forces HTTP.sys (or the managed
                // .NET implementation on non-Windows operating systems) to automatically reject requests
                // that don't include a Host header (e.g HTTP/1.0 requests) or specify an invalid value.

                { Request.Url: { IsAbsoluteUri: true } uri } => (
                    BaseUri: new UriBuilder(uri) { Path = null, Query = null, Fragment = null }.Uri,
                    RequestUri: uri),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0390))
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the request URI from the protocol activation details.
    /// Note: this handler is not used when the OpenID Connect request is not a protocol activation.
    /// </summary>
    public sealed class ResolveRequestUriFromProtocolActivation : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireProtocolActivation>()
                .UseSingletonHandler<ResolveRequestUriFromProtocolActivation>()
                .SetOrder(ResolveRequestUriFromHttpListenerRequest.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            (context.BaseUri, context.RequestUri) = context.Transaction.GetProtocolActivation() switch
            {
                { ActivationUri: Uri uri } => (
                    BaseUri: new UriBuilder(uri) { Path = null, Query = null, Fragment = null }.Uri,
                    RequestUri: uri),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0375))
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the request URI from the web authentication result.
    /// Note: this handler is not used when the OpenID Connect request is not a web authentication result.
    /// </summary>
    public sealed class ResolveRequestUriFromWebAuthenticationResult : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireWebAuthenticationResult>()
                .UseSingletonHandler<ResolveRequestUriFromWebAuthenticationResult>()
                .SetOrder(ResolveRequestUriFromProtocolActivation.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

#if SUPPORTS_WINDOWS_RUNTIME
            (context.BaseUri, context.RequestUri) = context.Transaction.GetWebAuthenticationResult() switch
            {
                { ResponseStatus: WebAuthenticationStatus.Success, ResponseData: string data } when
                    Uri.TryCreate(data, UriKind.Absolute, out Uri? uri) => (
                        BaseUri: new UriBuilder(uri) { Path = null, Query = null, Fragment = null }.Uri,
                        RequestUri: uri),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0393))
            };

            return default;
#else
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0392));
#endif
        }
    }

    /// <summary>
    /// Contains the logic responsible for inferring the endpoint type from the request URI, ignoring
    /// the port when comparing the request URI with the endpoint URIs configured in the options.
    /// Note: this handler is not used when the OpenID Connect request is not handled by the embedded web server.
    /// </summary>
    public sealed class InferEndpointTypeFromDynamicAddress : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireHttpListenerContext>()
                .UseSingletonHandler<InferEndpointTypeFromDynamicAddress>()
                .SetOrder(InferEndpointType.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context is not { BaseUri.IsAbsoluteUri: true, RequestUri.IsAbsoluteUri: true })
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0127));
            }

            // If an endpoint was already inferred by the generic handler, don't override it.
            if (context.EndpointType is not OpenIddictClientEndpointType.Unknown)
            {
                return default;
            }

            context.EndpointType =
                Matches(context.Options.RedirectionEndpointUris)           ? OpenIddictClientEndpointType.Redirection           :
                Matches(context.Options.PostLogoutRedirectionEndpointUris) ? OpenIddictClientEndpointType.PostLogoutRedirection :
                                                                             OpenIddictClientEndpointType.Unknown;

            return default;

            bool Matches(IReadOnlyList<Uri> uris)
            {
                for (var index = 0; index < uris.Count; index++)
                {
                    var uri = uris[index];
                    if (uri.IsAbsoluteUri && uri.IsLoopback && uri.IsDefaultPort && Equals(uri, context.RequestUri))
                    {
                        return true;
                    }
                }

                return false;
            }

            static bool Equals(Uri left, Uri right) =>
                string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(left.Host, right.Host, StringComparison.OrdinalIgnoreCase) &&
                //
                // Deliberately ignore the port when doing comparisons in this specialized handler.
                //
                // Note: paths are considered equivalent even if the casing isn't identical or if one of the two
                // paths only differs by a trailing slash, which matches the classical behavior seen on ASP.NET,
                // Microsoft.Owin/Katana and ASP.NET Core. Developers who prefer a different behavior can remove
                // this handler and replace it by a custom version implementing a more strict comparison logic.
                (string.Equals(left.AbsolutePath, right.AbsolutePath, StringComparison.OrdinalIgnoreCase) ||
                 (left.AbsolutePath.Length == right.AbsolutePath.Length + 1 &&
                  left.AbsolutePath.StartsWith(right.AbsolutePath, StringComparison.OrdinalIgnoreCase) &&
                  left.AbsolutePath[^1] is '/') ||
                 (right.AbsolutePath.Length == left.AbsolutePath.Length + 1 &&
                  right.AbsolutePath.StartsWith(left.AbsolutePath, StringComparison.OrdinalIgnoreCase) &&
                  right.AbsolutePath[^1] is '/'));
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting unknown requests handled by the embedded web server, if applicable.
    /// Note: this handler is not used when the OpenID Connect request is not handled by the embedded web server.
    /// </summary>
    public sealed class RejectUnknownHttpRequests : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireHttpListenerContext>()
                .UseSingletonHandler<RejectUnknownHttpRequests>()
                .SetOrder(InferEndpointTypeFromDynamicAddress.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to HTTP listener requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpListenerContext()?.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0390));

            // Unlike the ASP.NET Core or OWIN hosts, the embedded server instantiated by the system
            // integration is not meant to handle requests pointing to user-defined HTTP endpoints.
            // At such, reject all HTTP requests whose address doesn't match an OpenIddict endpoint.
            if (context.EndpointType is OpenIddictClientEndpointType.Unknown)
            {
                response.StatusCode = (int) HttpStatusCode.NotFound;

                context.HandleRequest();
                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from the HTTP listener request.
    /// Note: this handler is not used when the OpenID Connect request is not handled by the embedded web server.
    /// </summary>
    public sealed class ExtractGetHttpListenerRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpListenerContext>()
                .UseSingletonHandler<ExtractGetHttpListenerRequest<TContext>>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to HTTP listener requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpListenerContext()?.Request ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0390));

            // If the incoming request doesn't use GET, reject it.
            if (!string.Equals(request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6137), request.HttpMethod);

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2084),
                    uri: SR.FormatID8000(SR.ID2084));

                return default;
            }

            context.Transaction.Request = request.QueryString.AllKeys.Length switch
            {
                0 => new OpenIddictRequest(),
                _ => new OpenIddictRequest(AsEnumerable(request.QueryString))
            };

            return default;
            
            static IEnumerable<KeyValuePair<string, StringValues>> AsEnumerable(NameValueCollection collection)
            {
                for (var index = 0; index < collection.AllKeys.Length; index++)
                {
                    var name = collection.AllKeys[index];
                    if (!string.IsNullOrEmpty(name))
                    {
                        yield return new(name, collection.GetValues(name));
                    }
                }
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests
    /// from the URI of an initial or redirected protocol activation.
    /// Note: this handler is not used when the OpenID Connect request is not a protocol activation.
    /// </summary>
    public sealed class ExtractProtocolActivationParameters<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireProtocolActivation>()
                .UseSingletonHandler<ExtractProtocolActivationParameters<TContext>>()
                .SetOrder(ExtractGetHttpListenerRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Transaction.Request = context.Transaction.GetProtocolActivation() switch
            {
                { ActivationUri: Uri uri } => new OpenIddictRequest(OpenIddictHelpers.ParseQuery(uri.Query)),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0375))
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect
    /// requests from the response data of a web authentication result.
    /// Note: this handler is not used when the OpenID Connect request is not a web authentication result.
    /// </summary>
    public sealed class ExtractWebAuthenticationResultData<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireWebAuthenticationResult>()
                .UseSingletonHandler<ExtractWebAuthenticationResultData<TContext>>()
                .SetOrder(ExtractProtocolActivationParameters<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

#if SUPPORTS_WINDOWS_RUNTIME
            context.Transaction.Request = context.Transaction.GetWebAuthenticationResult() switch
            {
                { ResponseStatus: WebAuthenticationStatus.Success, ResponseData: string data } when
                    Uri.TryCreate(data, UriKind.Absolute, out Uri? uri)
                        => new OpenIddictRequest(OpenIddictHelpers.ParseQuery(uri.Query)),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0393))
            };

            return default;
#else
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0392));
#endif
        }
    }

    /// <summary>
    /// Contains the logic responsible for waiting for the marshalled authentication operation to complete, if applicable.
    /// </summary>
    public sealed class WaitMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;
        private readonly IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> _options;

        public WaitMarshalledAuthentication(
            OpenIddictClientSystemIntegrationMarshal marshal,
            IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> options)
        {
            _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<WaitMarshalledAuthentication>()
                .SetOrder(ValidateAuthenticationDemand.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // Skip the marshalling logic entirely if the operation is not tracked.
            if (!_marshal.IsTracked(context.Nonce))
            {
                return;
            }

            // Allow a single authentication operation at the same time with the same nonce.
            if (!_marshal.TryAcquireLock(context.Nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0379));
            }

            // At this point, user authentication demands cannot complete until the authorization response has been
            // returned to the redirection endpoint (materialized as a registered protocol activation URI) and handled
            // by OpenIddict via the ProcessRequest event. Since it is asynchronous by nature, this process requires
            // using a signal mechanism to unblock the authentication operation once it is complete. For that, the
            // marshal uses a TaskCompletionSource (one per authentication) that will be automatically completed
            // or aborted by a specialized event handler as part of the ProcessRequest/ProcessError events processing.

            try
            {
                // To ensure pending authentication operations for which no response is received are not tracked
                // indefinitely, a CancellationTokenSource with a static timeout is used even if the cancellation
                // token specified by the user is never marked as canceled: if the authentication is not completed
                // when the timeout is reached, the operation will be considered canceled and removed from the list.
                using var source = CancellationTokenSource.CreateLinkedTokenSource(context.CancellationToken);
                source.CancelAfter(_options.CurrentValue.AuthenticationTimeout);

                if (!await _marshal.TryWaitForCompletionAsync(context.Nonce, source.Token) ||
                    !_marshal.TryGetResult(context.Nonce, out ProcessAuthenticationContext? notification))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0383));
                }

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

            // If the operation failed due to the timeout, it's likely the TryRemove() method
            // won't be called, so the tracked context is manually removed before re-throwing.
            catch (OperationCanceledException) when (_marshal.TryRemove(context.Nonce))
            {
                throw;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the state token
    /// from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreStateTokenFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreStateTokenFromMarshalledAuthentication(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreStateTokenFromMarshalledAuthentication>()
                .SetOrder(ResolveValidatedStateToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.StateToken = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the state token from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => notification.StateToken,

                // Otherwise, don't alter the current context.
                _ => context.StateToken
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the state token
    /// principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreStateTokenPrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreStateTokenPrincipalFromMarshalledAuthentication(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreStateTokenPrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateStateToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.StateTokenPrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore
                // the state token principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => notification.StateTokenPrincipal,

                // Otherwise, don't alter the current context.
                _ => context.StateTokenPrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the client registration and
    /// configuration from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreClientRegistrationFromMarshalledContext : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreClientRegistrationFromMarshalledContext(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreClientRegistrationFromMarshalledContext>()
                .SetOrder(ResolveClientRegistrationFromStateToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            (context.Issuer, context.Configuration, context.Registration) = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the
                // issuer registration and configuration from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => (notification.Issuer, notification.Configuration, notification.Registration),

                _ => (context.Issuer, context.Configuration, context.Registration)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for redirecting the Windows protocol activation
    /// to the instance that initially started the authentication demand, if applicable.
    /// Note: this handler is not used when the OpenID Connect request is not a protocol activation.
    /// </summary>
    public sealed class RedirectProtocolActivation : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IHostApplicationLifetime _lifetime;
        private readonly IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> _options;
        private readonly OpenIddictClientSystemIntegrationService _service;

        public RedirectProtocolActivation(
            IHostApplicationLifetime lifetime,
            IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> options,
            OpenIddictClientSystemIntegrationService service)
        {
            _lifetime = lifetime ?? throw new ArgumentNullException(nameof(lifetime));
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _service = service ?? throw new ArgumentNullException(nameof(service));
        }

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireProtocolActivation>()
                .AddFilter<RequireStateTokenPrincipal>()
                .UseSingletonHandler<RedirectProtocolActivation>()
                .SetOrder(ResolveNonceFromStateToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            var activation = context.Transaction.GetProtocolActivation() ??
                 throw new InvalidOperationException(SR.GetResourceString(SR.ID0375));

            var identifier = context.StateTokenPrincipal.GetClaim(Claims.Private.InstanceId);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0376));
            }

            // If the identifier stored in the state token doesn't match the identifier of the
            // current instance, stop processing the authentication demand in this process and
            // redirect the protocol activation to the correct instance. Once the redirection
            // has been received by the other instance, ask the host to stop the application.

            if (string.Equals(identifier, _options.CurrentValue.InstanceIdentifier, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            // If protocol activation redirection was not enabled, reject the request
            // as there's no additional processing that can be made at this stage.
            if (_options.CurrentValue.EnableActivationRedirection is not true)
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2166),
                    uri: SR.FormatID8000(SR.ID2166));

                return;
            }

            // Try to redirect the protocol activation to the correct instance.
            try
            {
                using var source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(10));
                await _service.RedirectProtocolActivationAsync(activation, identifier, source.Token);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                context.Logger.LogWarning(SR.GetResourceString(SR.ID6215), identifier);
            }

            // Inform the host that the application should stop and mark the authentication context as handled
            // to prevent the other event handlers from being invoked while the application is shutting down.
            _lifetime.StopApplication();
            context.HandleRequest();
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the request forgery protection that serves as a
    /// protection against state token injection, forged requests and session fixation attacks.
    /// </summary>
    public sealed class ResolveRequestForgeryProtection : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public ResolveRequestForgeryProtection(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRedirectionRequest>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<ResolveRequestForgeryProtection>()
                .SetOrder(ValidateRequestForgeryProtection.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // Ensure the authentication demand is tracked by the OpenIddict client Windows marshal
            // and resolve the corresponding request forgery protection. If it can't be found, this may
            // indicate a session fixation attack: in this case, reject the authentication demand.
            if (!_marshal.TryGetRequestForgeryProtection(context.Nonce, out string? protection))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2139),
                    uri: SR.FormatID8000(SR.ID2139));

                return default;
            }

            context.RequestForgeryProtection = protection;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the frontchannel tokens
    /// from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreFrontchannelTokensFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreFrontchannelTokensFromMarshalledAuthentication(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreFrontchannelTokensFromMarshalledAuthentication>()
                .SetOrder(ResolveValidatedFrontchannelTokens.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            (context.AuthorizationCode,
             context.FrontchannelAccessToken,
             context.FrontchannelIdentityToken) = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the tokens from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => (notification.AuthorizationCode, notification.FrontchannelAccessToken, notification.FrontchannelIdentityToken),

                // Otherwise, don't alter the current context.
                _ => (context.AuthorizationCode, context.FrontchannelAccessToken, context.FrontchannelIdentityToken)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the frontchannel identity
    /// token principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreFrontchannelIdentityTokenPrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreFrontchannelIdentityTokenPrincipalFromMarshalledAuthentication(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreFrontchannelIdentityTokenPrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateFrontchannelIdentityToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.FrontchannelIdentityTokenPrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the
                // frontchannel identity token principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => notification.FrontchannelIdentityTokenPrincipal,

                // Otherwise, don't alter the current context.
                _ => context.FrontchannelIdentityTokenPrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the frontchannel access
    /// token principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreFrontchannelAccessTokenPrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreFrontchannelAccessTokenPrincipalFromMarshalledAuthentication(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreFrontchannelAccessTokenPrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateFrontchannelAccessToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.FrontchannelAccessTokenPrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the
                // frontchannel access token principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => notification.FrontchannelAccessTokenPrincipal,

                // Otherwise, don't alter the current context.
                _ => context.FrontchannelAccessTokenPrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the authorization code
    /// principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreAuthorizationCodePrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreAuthorizationCodePrincipalFromMarshalledAuthentication(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreAuthorizationCodePrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateAuthorizationCode.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.AuthorizationCodePrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the
                // authorization code principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => notification.AuthorizationCodePrincipal,

                // Otherwise, don't alter the current context.
                _ => context.AuthorizationCodePrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the token response
    /// from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreTokenResponseFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreTokenResponseFromMarshalledAuthentication(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreTokenResponseFromMarshalledAuthentication>()
                .SetOrder(SendTokenRequest.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.TokenResponse = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the token response from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => notification.TokenResponse,

                // Otherwise, don't alter the current context.
                _ => context.TokenResponse
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the backchannel tokens
    /// from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreBackchannelTokensFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreBackchannelTokensFromMarshalledAuthentication(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreBackchannelTokensFromMarshalledAuthentication>()
                .SetOrder(ResolveValidatedBackchannelTokens.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            (context.BackchannelAccessToken,
             context.BackchannelIdentityToken,
             context.RefreshToken) = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the tokens from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => (notification.BackchannelAccessToken, notification.BackchannelIdentityToken, notification.RefreshToken),

                // Otherwise, don't alter the current context.
                _ => (context.BackchannelAccessToken, context.BackchannelIdentityToken, context.RefreshToken)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the backchannel identity
    /// token principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreBackchannelIdentityTokenPrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreBackchannelIdentityTokenPrincipalFromMarshalledAuthentication(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreBackchannelIdentityTokenPrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateBackchannelIdentityToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.BackchannelIdentityTokenPrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the
                // frontchannel identity token principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => notification.BackchannelIdentityTokenPrincipal,

                // Otherwise, don't alter the current context.
                _ => context.BackchannelIdentityTokenPrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the frontchannel access
    /// token principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreBackchannelAccessTokenPrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreBackchannelAccessTokenPrincipalFromMarshalledAuthentication(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreBackchannelAccessTokenPrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateBackchannelAccessToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.BackchannelAccessTokenPrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the
                // frontchannel access token principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => notification.BackchannelAccessTokenPrincipal,

                // Otherwise, don't alter the current context.
                _ => context.BackchannelAccessTokenPrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the refresh token
    /// principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreRefreshTokenPrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreRefreshTokenPrincipalFromMarshalledAuthentication(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreRefreshTokenPrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateRefreshToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.RefreshTokenPrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore
                // the refresh token principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => notification.RefreshTokenPrincipal,

                // Otherwise, don't alter the current context.
                _ => context.RefreshTokenPrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the userinfo details
    /// from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreUserinfoDetailsFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreUserinfoDetailsFromMarshalledAuthentication(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreUserinfoDetailsFromMarshalledAuthentication>()
                .SetOrder(ValidateUserinfoTokenSubject.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            (context.UserinfoResponse, context.UserinfoTokenPrincipal, context.UserinfoToken) = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the userinfo details from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => (notification.UserinfoResponse, notification.UserinfoTokenPrincipal, notification.UserinfoToken),

                // Otherwise, don't alter the current context.
                _ => (context.UserinfoResponse, context.UserinfoTokenPrincipal, context.UserinfoToken)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for informing the authentication service the operation is complete.
    /// </summary>
    public sealed class CompleteAuthenticationOperation : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public CompleteAuthenticationOperation(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRedirectionRequest>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<CompleteAuthenticationOperation>()
                .SetOrder(int.MaxValue - 50_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // Inform the marshal that the authentication demand is complete.
            if (!_marshal.TryComplete(context.Nonce, context))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0380));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for informing the marshal that the context
    /// associated with the authentication operation can be discarded, if applicable.
    /// </summary>
    public sealed class UntrackMarshalledAuthenticationOperation : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public UntrackMarshalledAuthenticationOperation(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<UntrackMarshalledAuthenticationOperation>()
                .SetOrder(int.MaxValue)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // If applicable, inform the marshal that the authentication demand can be discarded.
            if (context.EndpointType is OpenIddictClientEndpointType.Unknown &&
                _marshal.IsTracked(context.Nonce) && !_marshal.TryRemove(context.Nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0381));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for inferring the base URI from the client URI set in the options.
    /// Note: this handler is not used when the user session is not interactive.
    /// </summary>
    public sealed class InferBaseUriFromClientUri : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveSession>()
                .UseSingletonHandler<InferBaseUriFromClientUri>()
                .SetOrder(ValidateChallengeDemand.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.BaseUri ??= context.Options.ClientUri;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the listening port
    /// of the embedded web server to the redirect_uri, if applicable.
    /// Note: this handler is not used when the user session is not interactive.
    /// </summary>
    public sealed class AttachDynamicPortToRedirectUri : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        private readonly OpenIddictClientSystemIntegrationHttpListener _listener;

        public AttachDynamicPortToRedirectUri(OpenIddictClientSystemIntegrationHttpListener listener)
            => _listener = listener ?? throw new ArgumentNullException(nameof(listener));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveSession>()
                .UseSingletonHandler<AttachDynamicPortToRedirectUri>()
                .SetOrder(AttachRedirectUri.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // If the redirect_uri uses a loopback host/IP as the authority and doesn't include a non-default port,
            // determine whether the embedded web server is running: if so, override the port in the redirect_uri
            // by the port used by the embedded web server (guaranteed to be running if a value is returned).
            if (!string.IsNullOrEmpty(context.RedirectUri) &&
                Uri.TryCreate(context.RedirectUri, UriKind.Absolute, out Uri? uri) &&
                string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                uri.IsLoopback && uri.IsDefaultPort &&
                await _listener.GetEmbeddedServerPortAsync(context.CancellationToken) is int port)
            {
                var builder = new UriBuilder(context.RedirectUri)
                {
                    Port = port
                };

                context.RedirectUri = builder.Uri.AbsoluteUri;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for storing the identifier of the current instance in the state token.
    /// Note: this handler is not used when the user session is not interactive.
    /// </summary>
    public sealed class AttachInstanceIdentifier : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> _options;

        public AttachInstanceIdentifier(IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveSession>()
                .AddFilter<RequireLoginStateTokenGenerated>()
                .UseSingletonHandler<AttachInstanceIdentifier>()
                .SetOrder(PrepareLoginStateTokenPrincipal.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Most applications (except Windows UWP applications) are multi-instanced. As such, any protocol activation
            // triggered by launching one of the URI schemes associated with the application will create a new instance,
            // different from the one that initially started the authentication flow. To deal with that without having to
            // share persistent state between instances, OpenIddict stores the identifier of the instance that starts the
            // authentication process and uses it when handling the callback to determine whether the protocol activation
            // should be redirected to a different instance using inter-process communication.
            context.StateTokenPrincipal.SetClaim(Claims.Private.InstanceId, _options.CurrentValue.InstanceIdentifier);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for asking the marshal to track the authentication operation.
    /// Note: this handler is not used when the user session is not interactive.
    /// </summary>
    public sealed class TrackAuthenticationOperation : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public TrackAuthenticationOperation(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveSession>()
                .AddFilter<RequireLoginStateTokenGenerated>()
                .UseSingletonHandler<TrackAuthenticationOperation>()
                .SetOrder(100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (string.IsNullOrEmpty(context.Nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0352));
            }

            if (string.IsNullOrEmpty(context.RequestForgeryProtection))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0343));
            }

            if (!_marshal.TryAdd(context.Nonce, context.RequestForgeryProtection))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0378));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for informing the authentication service the demand is aborted.
    /// </summary>
    public sealed class AbortAuthenticationDemand : IOpenIddictClientHandler<ProcessErrorContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;
        private readonly IHostApplicationLifetime _lifetime;

        public AbortAuthenticationDemand(
            OpenIddictClientSystemIntegrationMarshal marshal,
            IHostApplicationLifetime lifetime)
        {
            _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));
            _lifetime = lifetime ?? throw new ArgumentNullException(nameof(lifetime));
        }

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessErrorContext>()
                .UseSingletonHandler<AbortAuthenticationDemand>()
                .SetOrder(100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessErrorContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Try to resolve the authentication context from the transaction, if available.
            var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                typeof(ProcessAuthenticationContext).FullName!);

            // If the context is available, resolve the nonce used to track the marshalled authentication
            // and inform the marshal so that the context can be marshalled back to the initiator.
            if (!string.IsNullOrEmpty(notification?.Nonce) && !_marshal.TryComplete(notification.Nonce, notification))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0382));
            }

            // If the current application instance was created to react to a protocol activation (assumed to be
            // managed by OpenIddict at this stage), terminate it to prevent the UI thread from being started.
            // By doing that, unsolicited requests will be discarded without the user seeing flashing windows.
            if (context.Transaction.GetProtocolActivation() is { IsActivationRedirected: false })
            {
                _lifetime.StopApplication();

                context.HandleRequest();
                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching an appropriate HTTP status code.
    /// Note: this handler is not used when the OpenID Connect request is not handled by the embedded web server.
    /// </summary>
    public sealed class AttachHttpResponseCode<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpListenerContext>()
                .UseSingletonHandler<AttachHttpResponseCode<TContext>>()
                .SetOrder(100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to HTTP listener requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpListenerContext()?.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0390));

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            response.StatusCode = context.Transaction.Response.Error switch
            {
                null => 200, // Note: the default code may be replaced by another handler (e.g when doing redirects).

                _ => 400
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the appropriate HTTP response cache headers.
    /// Note: this handler is not used when the OpenID Connect request is not handled by the embedded web server.
    /// </summary>
    public sealed class AttachCacheControlHeader<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpListenerContext>()
                .UseSingletonHandler<AttachCacheControlHeader<TContext>>()
                .SetOrder(AttachHttpResponseCode<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to HTTP listener requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpListenerContext()?.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0390));

            // Prevent the response from being cached.
            response.Headers[Headers.CacheControl] = "no-store";
            response.Headers[Headers.Pragma] = "no-cache";
            response.Headers[Headers.Expires] = "Thu, 01 Jan 1970 00:00:00 GMT";

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for marking OpenID Connect responses
    /// returned via protocol activations or web authentication results as processed.
    /// </summary>
    public sealed class ProcessUnactionableResponse<TContext> : IOpenIddictClientHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .UseSingletonHandler<ProcessUnactionableResponse<TContext>>()
                .SetOrder(int.MaxValue)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // For both protocol activations (initial or redirected) and web-view-like results,
            // no proper response can be generated and eventually displayed to the user. In this
            // case, simply stop processing the response and mark the request as fully handled.
            //
            // Note: this logic applies to both successful and errored responses.

            if (context.Transaction.GetProtocolActivation() is not null)
            {
                context.HandleRequest();
                return default;
            }

#if SUPPORTS_WINDOWS_RUNTIME
            if (context.Transaction.GetWebAuthenticationResult() is not null)
            {
                context.HandleRequest();
                return default;
            }
#endif
            return default;
        }
    }
}
