/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using static OpenIddict.Client.SystemIntegration.OpenIddictClientSystemIntegrationConstants;

namespace OpenIddict.Client.SystemIntegration;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictClientSystemIntegrationHandlers
{
    public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } =
    [
        /*
         * Top-level request processing:
         */
        ResolveRequestUriFromHttpListenerRequest.Descriptor,
        ResolveRequestUriFromProtocolActivation.Descriptor,
        ResolveRequestUriFromPlatformCallback.Descriptor,
        InferEndpointTypeFromDynamicAddress.Descriptor,
        RejectUnknownHttpRequests.Descriptor,

        /*
         * Authentication processing:
         */
        WaitMarshalledAuthentication.Descriptor,

        RestoreRequestFromMarshalledContext.Descriptor,
        RestoreClientRegistrationFromMarshalledContext.Descriptor,

        EvaluateValidatedUpfrontTokensForMarshalledContext.Descriptor,
        ResolveValidatedStateTokenFromMarshalledContext.Descriptor,
        EvaluateValidatedFrontchannelTokensForMarshalledContext.Descriptor,
        ResolveValidatedFrontchannelTokensFromMarshalledContext.Descriptor,
        EvaluateValidatedBackchannelTokensForMarshalledContext.Descriptor,

        DisableStateTokenRedeeming.Descriptor,
        DisableTokenRequestSending.Descriptor,
        DisableUserInfoRequestSending.Descriptor,

        RedirectProtocolActivation.Descriptor,
        ResolveRequestForgeryProtection.Descriptor,

        CompleteAuthenticationOperation.Descriptor,
        UntrackMarshalledAuthenticationOperation.Descriptor,

        /*
         * Challenge processing:
         */
        InferBaseUriFromClientUri.Descriptor,
        AttachDynamicPortToRedirectUri.Descriptor,
        AttachNonDefaultResponseMode.Descriptor,
        AttachInstanceIdentifier.Descriptor,
        TrackAuthenticationOperation.Descriptor,

        /*
         * Sign-out processing:
         */
        InferLogoutBaseUriFromClientUri.Descriptor,
        AttachDynamicPortToPostLogoutRedirectUri.Descriptor,
        AttachLogoutInstanceIdentifier.Descriptor,
        TrackLogoutOperation.Descriptor,

        /*
         * Error processing:
         */
        AbortAuthenticationDemand.Descriptor,

        .. Authentication.DefaultHandlers,
        .. Session.DefaultHandlers
    ];

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
            ArgumentNullException.ThrowIfNull(context);

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

            return ValueTask.CompletedTask;
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
            ArgumentNullException.ThrowIfNull(context);

            (context.BaseUri, context.RequestUri) = context.Transaction.GetProtocolActivation() switch
            {
                { ActivationUri: Uri uri } => (
                    BaseUri: new UriBuilder(uri) { Path = null, Query = null, Fragment = null }.Uri,
                    RequestUri: uri),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0375))
            };

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the request URI from the platform callback details.
    /// Note: this handler is not used when the OpenID Connect request is not a platform callback.
    /// </summary>
    public sealed class ResolveRequestUriFromPlatformCallback : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequirePlatformCallback>()
                .UseSingletonHandler<ResolveRequestUriFromPlatformCallback>()
                .SetOrder(ResolveRequestUriFromProtocolActivation.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            (context.BaseUri, context.RequestUri) = context.Transaction.GetPlatformCallback() switch
            {
                { CallbackUri: Uri uri } => (
                    BaseUri: new UriBuilder(uri) { Path = null, Query = null, Fragment = null }.Uri,
                    RequestUri: uri),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0393))
            };

            return ValueTask.CompletedTask;
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
            ArgumentNullException.ThrowIfNull(context);

            // If the base or request URIs couldn't be resolved, don't try to infer the endpoint type.
            if (context is not { BaseUri.IsAbsoluteUri: true, RequestUri.IsAbsoluteUri: true })
            {
                return ValueTask.CompletedTask;
            }

            // If an endpoint was already inferred by the generic handler, don't override it.
            if (context.EndpointType is not OpenIddictClientEndpointType.Unknown)
            {
                return ValueTask.CompletedTask;
            }

            context.EndpointType =
                Matches(context.Options.RedirectionEndpointUris)           ? OpenIddictClientEndpointType.Redirection           :
                Matches(context.Options.PostLogoutRedirectionEndpointUris) ? OpenIddictClientEndpointType.PostLogoutRedirection :
                                                                             OpenIddictClientEndpointType.Unknown;

            return ValueTask.CompletedTask;

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
            ArgumentNullException.ThrowIfNull(context);

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
                return ValueTask.CompletedTask;
            }

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from GET HTTP listener requests.
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
            ArgumentNullException.ThrowIfNull(context);

            // This handler only applies to HTTP listener requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpListenerContext()?.Request ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0390));

            // If the incoming request doesn't use GET, reject it.
            if (!string.Equals(request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
            {
                context.Logger.LogInformation(6137, SR.GetResourceString(SR.ID6137), request.HttpMethod);

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2084),
                    uri: SR.FormatID8000(SR.ID2084));

                return ValueTask.CompletedTask;
            }

            context.Transaction.Request = request.QueryString.AllKeys.Length switch
            {
                0 => new OpenIddictRequest(),
                _ => new OpenIddictRequest(request.QueryString)
            };

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from GET or POST HTTP listener requests.
    /// Note: this handler is not used when the OpenID Connect request is not handled by the embedded web server.
    /// </summary>
    public sealed class ExtractGetOrPostHttpListenerRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpListenerContext>()
                .UseSingletonHandler<ExtractGetOrPostHttpListenerRequest<TContext>>()
                .SetOrder(ExtractGetHttpListenerRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // This handler only applies to HTTP listener requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpListenerContext()?.Request ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0390));

            if (string.Equals(request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
            {
                context.Transaction.Request = request.QueryString.AllKeys.Length switch
                {
                    0 => new OpenIddictRequest(),
                    _ => new OpenIddictRequest(request.QueryString)
                };
            }

            else if (string.Equals(request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization for more information.
                if (!MediaTypeHeaderValue.TryParse(request.ContentType, out MediaTypeHeaderValue? type) ||
                    StringSegment.IsNullOrEmpty(type.MediaType))
                {
                    context.Logger.LogInformation(6138, SR.GetResourceString(SR.ID6138), "Content-Type");

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2081("Content-Type"),
                        uri: SR.FormatID8000(SR.ID2081));

                    return;
                }

                if (!StringSegment.Equals(type.MediaType, "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    context.Logger.LogInformation(6139, SR.GetResourceString(SR.ID6139), "Content-Type", request.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2082("Content-Type"),
                        uri: SR.FormatID8000(SR.ID2082));

                    return;
                }

                // Note: do not allow the unsafe UTF-7 encoding to be used, even if explicitly set.
                // If no encoding was set or if the received value is not valid, fall back to UTF-8.
                context.Transaction.Request = new OpenIddictRequest(await OpenIddictHelpers.ParseFormAsync(
                    stream           : request.InputStream,
                    encoding         : GetEncoding(type) is { CodePage: not 65000 } encoding ? encoding : Encoding.UTF8,
                    cancellationToken: CancellationToken.None));
            }

            else
            {
                context.Logger.LogInformation(6137, SR.GetResourceString(SR.ID6137), request.HttpMethod);

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2084),
                    uri: SR.FormatID8000(SR.ID2084));

                return;
            }

            static Encoding? GetEncoding(MediaTypeHeaderValue type)
            {
                if (string.IsNullOrEmpty(type.CharSet))
                {
                    return null;
                }

                try
                {
                    return Encoding.GetEncoding(type.CharSet);
                }

                catch (ArgumentException)
                {
                    return null;
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
                .SetOrder(ExtractGetOrPostHttpListenerRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            if (context.Transaction.GetProtocolActivation() is not { ActivationUri: Uri uri })
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0375));
            }

            var parameters = new Dictionary<string, StringValues>(StringComparer.Ordinal);

            if (!string.IsNullOrEmpty(uri.Query))
            {
                foreach (var parameter in OpenIddictHelpers.ParseQuery(uri.Query))
                {
                    parameters[parameter.Key] = parameter.Value;
                }
            }

            // Note: the fragment is always processed after the query string to ensure that
            // parameters extracted from the fragment are preferred to parameters extracted
            // from the query string when they are present in both parts.

            if (!string.IsNullOrEmpty(uri.Fragment))
            {
                foreach (var parameter in OpenIddictHelpers.ParseFragment(uri.Fragment))
                {
                    parameters[parameter.Key] = parameter.Value;
                }
            }

            context.Transaction.Request = new OpenIddictRequest(parameters);

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from the URI of a platform callback.
    /// Note: this handler is not used when the OpenID Connect request is not a platform callback.
    /// </summary>
    public sealed class ExtractPlatformCallbackParameters<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequirePlatformCallback>()
                .UseSingletonHandler<ExtractPlatformCallbackParameters<TContext>>()
                .SetOrder(ExtractProtocolActivationParameters<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            if (context.Transaction.GetPlatformCallback() is not OpenIddictClientSystemIntegrationPlatformCallback callback)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0393));
            }

            context.Transaction.Request = new OpenIddictRequest(callback.Parameters);

            return ValueTask.CompletedTask;
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
                .SetOrder(ValidateAuthenticationDemand.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // Skip the marshalling logic entirely if the operation is not tracked.
            if (!_marshal.IsTracked(context.Nonce))
            {
                return;
            }

            // Allow a single authentication operation at the same time with the same nonce.
            if (!await _marshal.TryAcquireLockAsync(context.Nonce, context.CancellationToken))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0379));
            }

            // At this point, the user authentication demand cannot complete until the authorization response has been
            // returned to the redirection endpoint (materialized as a registered protocol activation URI) and handled
            // by OpenIddict via the ProcessRequest event. Since it is asynchronous by nature, this process requires
            // using a signal mechanism to unblock the authentication operation once it is complete. For that, the
            // marshal uses a TaskCompletionSource (one per authentication) that will be automatically completed or
            // aborted by a specialized event handler as part of the ProcessRequest/ProcessError events processing.

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
    /// Contains the logic responsible for restoring the request from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreRequestFromMarshalledContext : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public RestoreRequestFromMarshalledContext(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreRequestFromMarshalledContext>()
                .SetOrder(WaitMarshalledAuthentication.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.Request = context.EndpointType switch
            {
                // When the authentication demand is marshalled from a different context, restore the request from the
                // other instance so that custom parameters can be resolved from the marshalled context, if necessary.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => notification.Request,

                _ => context.Request
            };

            return ValueTask.CompletedTask;
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
                .SetOrder(ResolveClientRegistrationFromAuthenticationContext.Descriptor.Order - 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            (context.Configuration, context.Registration) = context.EndpointType switch
            {
                // When the authentication demand is marshalled from a different context,
                // restore the registration and configuration from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => (notification.Configuration, notification.Registration),

                _ => (context.Configuration, context.Registration)
            };

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for determining the types of
    /// tokens to validate upfront when the context is marshalled.
    /// </summary>
    public sealed class EvaluateValidatedUpfrontTokensForMarshalledContext : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public EvaluateValidatedUpfrontTokensForMarshalledContext(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<EvaluateValidatedUpfrontTokensForMarshalledContext>()
                .SetOrder(EvaluateValidatedUpfrontTokens.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // When the authentication demand is marshalled from a different context, always
            // extract and validate the state token to ensure the authentication details
            // contained in the state token principal can be used to validate the operation.
            if (context.EndpointType is OpenIddictClientEndpointType.Unknown && _marshal.IsTracked(context.Nonce))
            {
                context.ExtractStateToken = context.RequireStateToken = true;
                context.ValidateStateToken = context.RejectStateToken = true;
            }

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the state token to validate upfront from the marshalled context.
    /// </summary>
    public sealed class ResolveValidatedStateTokenFromMarshalledContext : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public ResolveValidatedStateTokenFromMarshalledContext(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<ResolveValidatedStateTokenFromMarshalledContext>()
                .SetOrder(ResolveValidatedStateToken.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.StateToken = context.EndpointType switch
            {
                // When the authentication demand is marshalled from a different context,
                // always restore the state token from the instance that extracted it.
                OpenIddictClientEndpointType.Unknown when _marshal.TryGetResult(context.Nonce, out var notification)
                    => notification.StateToken,

                _ => null
            };

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for determining the set of
    /// frontchannel tokens to validate when the context is marshalled.
    /// </summary>
    public sealed class EvaluateValidatedFrontchannelTokensForMarshalledContext : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public EvaluateValidatedFrontchannelTokensForMarshalledContext(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<EvaluateValidatedFrontchannelTokensForMarshalledContext>()
                .SetOrder(EvaluateValidatedFrontchannelTokens.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // When the authentication demand is expected to be marshalled to a different context,
            // always skip the validation of all the frontchannel tokens by default as the security
            // principals they contain are not needed to marshal the authentication demand.
            if (context.EndpointType is
                    OpenIddictClientEndpointType.Redirection or
                    OpenIddictClientEndpointType.PostLogoutRedirection && _marshal.IsTracked(context.Nonce))
            {
                context.ValidateAuthorizationCode = context.RejectAuthorizationCode = false;
                context.ValidateFrontchannelAccessToken = context.RejectFrontchannelAccessToken = false;
                context.ValidateFrontchannelIdentityToken = context.RejectFrontchannelIdentityToken = false;
            }

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the frontchannel tokens from the marshalled context.
    /// </summary>
    public sealed class ResolveValidatedFrontchannelTokensFromMarshalledContext : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public ResolveValidatedFrontchannelTokensFromMarshalledContext(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<ResolveValidatedFrontchannelTokensFromMarshalledContext>()
                .SetOrder(ResolveValidatedFrontchannelTokens.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // When the authentication context is marshalled, restore the frontchannel tokens from the other instance.
            if (context.EndpointType is OpenIddictClientEndpointType.Unknown &&
                _marshal.TryGetResult(context.Nonce, out var notification))
            {
                context.AuthorizationCode = notification.AuthorizationCode;
                context.FrontchannelAccessToken = notification.FrontchannelAccessToken;
                context.FrontchannelAccessTokenExpirationDate = notification.FrontchannelAccessTokenExpirationDate;
                context.FrontchannelIdentityToken = notification.FrontchannelIdentityToken;
            }

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for determining the set of
    /// backchannel tokens to validate when the context is marshalled.
    /// </summary>
    public sealed class EvaluateValidatedBackchannelTokensForMarshalledContext : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public EvaluateValidatedBackchannelTokensForMarshalledContext(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<EvaluateValidatedBackchannelTokensForMarshalledContext>()
                .SetOrder(EvaluateValidatedBackchannelTokens.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // When the authentication demand is expected to be marshalled to a different context,
            // always skip the validation of all the backchannel tokens by default as the security
            // principals they contain are not needed to marshal the authentication demand.
            if (context.EndpointType is
                OpenIddictClientEndpointType.Redirection or
                OpenIddictClientEndpointType.PostLogoutRedirection && _marshal.IsTracked(context.Nonce))
            {
                context.ValidateBackchannelAccessToken = context.RejectBackchannelAccessToken = false;
                context.ValidateBackchannelIdentityToken = context.RejectBackchannelIdentityToken = false;
                context.ValidateIssuedToken = context.RejectIssuedToken = false;
                context.ValidateRefreshToken = context.RejectRefreshToken = false;
            }

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for disabling the redeeming of the state token, if applicable.
    /// </summary>
    public sealed class DisableStateTokenRedeeming : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public DisableStateTokenRedeeming(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<DisableStateTokenRedeeming>()
                .SetOrder(RedeemStateTokenEntry.Descriptor.Order - 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.DisableStateTokenRedeeming = context.EndpointType switch
            {
                // When the authentication demand is expected to be marshalled to a different context,
                // disable the redeeming of the state token to ensure it is not in an invalid state
                // when the marshalled authentication demand is processed by the other instance.
                OpenIddictClientEndpointType.Redirection or
                OpenIddictClientEndpointType.PostLogoutRedirection when _marshal.IsTracked(context.Nonce)
                    => true,

                _ => context.DisableStateTokenRedeeming
            };

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preventing a token request from being sent, if applicable.
    /// </summary>
    public sealed class DisableTokenRequestSending : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public DisableTokenRequestSending(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<DisableTokenRequestSending>()
                .SetOrder(EvaluateTokenRequest.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.SendTokenRequest = context.EndpointType switch
            {
                // When the authentication demand is expected to be marshalled to a different
                // context, do not send a token request and let the other instance do it.
                OpenIddictClientEndpointType.Redirection or
                OpenIddictClientEndpointType.PostLogoutRedirection when _marshal.IsTracked(context.Nonce)
                    => false,

                _ => context.SendTokenRequest
            };

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preventing a userinfo request from being sent, if applicable.
    /// </summary>
    public sealed class DisableUserInfoRequestSending : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public DisableUserInfoRequestSending(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<DisableUserInfoRequestSending>()
                .SetOrder(EvaluateUserInfoRequest.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.SendUserInfoRequest = context.EndpointType switch
            {
                // When the authentication demand is expected to be marshalled to a different
                // context, do not send a userinfo request and let the other instance do it.
                OpenIddictClientEndpointType.Redirection or
                OpenIddictClientEndpointType.PostLogoutRedirection when _marshal.IsTracked(context.Nonce)
                    => false,

                _ => context.SendUserInfoRequest
            };

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for redirecting the protocol activation to
    /// the instance that initially started the authentication demand, if applicable.
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
            ArgumentNullException.ThrowIfNull(context);

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
                context.Logger.LogWarning(6215, SR.GetResourceString(SR.ID6215), identifier);
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
                .AddFilter<RequireAuthenticationNonce>()
                .AddFilter<RequireStateTokenPrincipal>()
                .AddFilter<RequireStateTokenValidated>()
                .UseSingletonHandler<ResolveRequestForgeryProtection>()
                .SetOrder(ValidateRequestForgeryProtection.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // Ensure the authentication demand is tracked by the OpenIddict client system integration
            // marshal and resolve the corresponding request forgery protection. If it can't be found,
            // this may indicate a session fixation attack: in this case, reject the authentication demand.
            if (!_marshal.TryGetRequestForgeryProtection(context.Nonce, out string? result))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2139),
                    uri: SR.FormatID8000(SR.ID2139));

                return ValueTask.CompletedTask;
            }

            context.RequestForgeryProtection = result;

            return ValueTask.CompletedTask;
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
                .AddFilter<RequireAuthenticationNonce>()
                .AddFilter<RequireStateTokenPrincipal>()
                .AddFilter<RequireStateTokenValidated>()
                .UseSingletonHandler<CompleteAuthenticationOperation>()
                .SetOrder(int.MaxValue - 50_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            if (context.EndpointType is not (OpenIddictClientEndpointType.Redirection or
                                             OpenIddictClientEndpointType.PostLogoutRedirection))
            {
                return ValueTask.CompletedTask;
            }

            if (_marshal.IsTracked(context.Nonce) && !_marshal.TryComplete(context.Nonce, context))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0380));
            }

            return ValueTask.CompletedTask;
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
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // If applicable, inform the marshal that the authentication demand can be discarded.
            if (context.EndpointType is OpenIddictClientEndpointType.Unknown &&
                _marshal.IsTracked(context.Nonce) && !_marshal.TryRemove(context.Nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0381));
            }

            return ValueTask.CompletedTask;
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
            ArgumentNullException.ThrowIfNull(context);

            context.BaseUri ??= context.Options.ClientUri;

            return ValueTask.CompletedTask;
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
                .AddFilter<RequireInteractiveGrantType>()
                .AddFilter<RequireEmbeddedWebServerEnabled>()
                // Note: only apply the dynamic port replacement logic if the callback request
                // is going to be received by the system browser to ensure it doesn't apply to
                // challenge demands handled via a web authentication broker.
                .AddFilter<RequireSystemBrowser>()
                .UseSingletonHandler<AttachDynamicPortToRedirectUri>()
                .SetOrder(AttachRedirectUri.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessChallengeContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // If the redirect_uri uses a loopback host/IP as the authority and doesn't include a non-default port,
            // determine whether the embedded web server is running: if so, override the port in the redirect_uri
            // by the port used by the embedded web server (guaranteed to be running if a value is returned).
            if (!string.IsNullOrEmpty(context.RedirectUri)                                       &&
                Uri.TryCreate(context.RedirectUri, UriKind.Absolute, out Uri? uri)               &&
                string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                uri.IsLoopback                                                                   &&
                uri.IsDefaultPort                                                                &&
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
    /// Contains the logic responsible for attaching a non-default response mode to the challenge request, if applicable.
    /// </summary>
    public sealed class AttachNonDefaultResponseMode : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        private readonly OpenIddictClientSystemIntegrationHttpListener _listener;
        private readonly IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> _options;

        public AttachNonDefaultResponseMode(
            OpenIddictClientSystemIntegrationHttpListener listener,
            IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> options)
        {
            _listener = listener ?? throw new ArgumentNullException(nameof(listener));
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveSession>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<AttachNonDefaultResponseMode>()
                .SetOrder(AttachResponseMode.Descriptor.Order - 500)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessChallengeContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // If an explicit response type was specified, don't overwrite it.
            if (!string.IsNullOrEmpty(context.ResponseMode))
            {
                return;
            }

            // Some specific response_type/response_mode combinations are not allowed (e.g response_mode=query
            // can never be used with a response type containing id_token or token, as required by the OAuth 2.0
            // multiple response types specification. To prevent invalid combinations from being sent to the
            // remote server, the response types are taken into account when selecting the best response mode.
            if (context.ResponseType?.Split(Separators.Space) is not IList<string> { Count: > 0 } types)
            {
                return;
            }

            context.ResponseMode = (
                // Note: if response modes are explicitly listed in the client registration, only use
                // the response modes that are both listed and enabled in the global client options.
                // Otherwise, always default to the response modes that have been enabled globally.
                SupportedClientResponseModes: context.Registration.ResponseModes.Count switch
                {
                    0 => context.Options.ResponseModes as ICollection<string>,
                    _ => context.Options.ResponseModes.Intersect(context.Registration.ResponseModes, StringComparer.Ordinal).ToList()
                },

                SupportedServerResponseModes: context.Configuration.ResponseModesSupported) switch
            {
                // When using the web authentication broker on Windows, if both the client and
                // the server support response_mode=fragment, use it if the response types contain
                // a value that prevents response_mode=query from being used (token/id_token).
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    IsWebAuthenticationBrokerSupported()                                                              &&
                    IsAuthenticationMode(OpenIddictClientSystemIntegrationAuthenticationMode.WebAuthenticationBroker) &&
                    client.Contains(ResponseModes.Fragment) && server.Contains(ResponseModes.Fragment)                &&
                    (types.Contains(ResponseTypes.IdToken) || types.Contains(ResponseTypes.Token))
                    => ResponseModes.Fragment,

                // When using the web authentication broker on Windows, if the client supports
                // response_mode=fragment and the server doesn't specify a list of response modes,
                // assume it is supported and use it if the response types contain a value that
                // prevents response_mode=query from being used (token/id_token).
                ({ Count: > 0 } client, { Count: 0 }) when
                    IsWebAuthenticationBrokerSupported()                                                              &&
                    IsAuthenticationMode(OpenIddictClientSystemIntegrationAuthenticationMode.WebAuthenticationBroker) &&
                    client.Contains(ResponseModes.Fragment)                                                           &&
                    (types.Contains(ResponseTypes.IdToken) || types.Contains(ResponseTypes.Token))
                    => ResponseModes.Fragment,

                // When using browser-based authentication with a redirect_uri not pointing to the embedded server,
                // if both the client and the server support response_mode=fragment, use it if the response types
                // contain a value that prevents response_mode=query from being used (token/id_token).
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    IsAuthenticationMode(OpenIddictClientSystemIntegrationAuthenticationMode.SystemBrowser) &&
                    !await IsEmbeddedWebServerRedirectUriAsync()                                            &&
                    client.Contains(ResponseModes.Fragment) && server.Contains(ResponseModes.Fragment)      &&
                    (types.Contains(ResponseTypes.IdToken) || types.Contains(ResponseTypes.Token))
                    => ResponseModes.Fragment,

                // When using browser-based authentication with a redirect_uri not pointing to the embedded server,
                // if the client supports response_mode=fragment and the server doesn't specify a list of response
                // modes, assume it is supported and use it if the response types contain a value that prevents
                // response_mode=query from being used (token/id_token).
                ({ Count: > 0 } client, { Count: 0 }) when
                    IsAuthenticationMode(OpenIddictClientSystemIntegrationAuthenticationMode.SystemBrowser) &&
                    !await IsEmbeddedWebServerRedirectUriAsync()                                            &&
                    client.Contains(ResponseModes.Fragment)                                                 &&
                    (types.Contains(ResponseTypes.IdToken) || types.Contains(ResponseTypes.Token))
                    => ResponseModes.Fragment,

                // When using browser-based authentication with a redirect_uri pointing to the embedded server,
                // if both the client and the server support response_mode=form_post, use it if the response
                // types contain a value that prevents response_mode=query from being used (token/id_token).
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    IsAuthenticationMode(OpenIddictClientSystemIntegrationAuthenticationMode.SystemBrowser) &&
                    await IsEmbeddedWebServerRedirectUriAsync()                                             &&
                    client.Contains(ResponseModes.FormPost) && server.Contains(ResponseModes.FormPost)      &&
                    (types.Contains(ResponseTypes.IdToken) || types.Contains(ResponseTypes.Token))
                    => ResponseModes.FormPost,

                // When using browser-based authentication with a redirect_uri pointing to the embedded server,
                // if the client supports response_mode=form_post and the server doesn't specify a list
                // of response modes, assume it is supported and use it if the response types contain
                // a value that prevents response_mode=query from being used (token/id_token).
                ({ Count: > 0 } client, { Count: 0 }) when
                    IsAuthenticationMode(OpenIddictClientSystemIntegrationAuthenticationMode.SystemBrowser) &&
                    await IsEmbeddedWebServerRedirectUriAsync()                                             &&
                    client.Contains(ResponseModes.FormPost)                                                 &&
                    (types.Contains(ResponseTypes.IdToken) || types.Contains(ResponseTypes.Token))
                    => ResponseModes.FormPost,

                // If both the client and the server support response_mode=query, use it.
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    client.Contains(ResponseModes.Query) && server.Contains(ResponseModes.Query)
                    => ResponseModes.Query,

                // If the client supports response_mode=query and the server doesn't
                // specify a list of response modes, assume it is supported.
                ({ Count: > 0 } client, { Count: 0 }) when client.Contains(ResponseModes.Query)
                    => ResponseModes.Query,

                // When using the web authentication broker on Windows, if both
                // the client and the server support response_mode=fragment, use it.
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    IsWebAuthenticationBrokerSupported()                                                              &&
                    IsAuthenticationMode(OpenIddictClientSystemIntegrationAuthenticationMode.WebAuthenticationBroker) &&
                    client.Contains(ResponseModes.Fragment) && server.Contains(ResponseModes.Fragment)
                    => ResponseModes.Fragment,

                // When using browser-based authentication with a redirect_uri not pointing to the embedded
                // server, if both the client and the server support response_mode=fragment, use it.
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    IsAuthenticationMode(OpenIddictClientSystemIntegrationAuthenticationMode.SystemBrowser) &&
                    !await IsEmbeddedWebServerRedirectUriAsync()                                            &&
                    client.Contains(ResponseModes.Fragment) && server.Contains(ResponseModes.Fragment)
                    => ResponseModes.Fragment,

                // When using browser-based authentication with a redirect_uri pointing to the embedded
                // server, if both the client and the server support response_mode=form_post, use it.
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    IsAuthenticationMode(OpenIddictClientSystemIntegrationAuthenticationMode.SystemBrowser) &&
                    await IsEmbeddedWebServerRedirectUriAsync()                                             &&
                    client.Contains(ResponseModes.FormPost) && server.Contains(ResponseModes.FormPost)
                    => ResponseModes.FormPost,

                // Assign a null value to allow the generic handler present in
                // the base client package to negotiate other response modes.
                _ => null
            };
            
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            bool IsAuthenticationMode(OpenIddictClientSystemIntegrationAuthenticationMode mode)
            {
                if (context.Transaction.Properties.TryGetValue(
                    typeof(OpenIddictClientSystemIntegrationAuthenticationMode).FullName!, out var result) &&
                    result is OpenIddictClientSystemIntegrationAuthenticationMode value)
                {
                    return mode == value;
                }

                return mode == _options.CurrentValue.AuthenticationMode;
            }

            async ValueTask<bool> IsEmbeddedWebServerRedirectUriAsync()
                => _options.CurrentValue.EnableEmbeddedWebServer is true                             &&
                    Uri.TryCreate(context.RedirectUri, UriKind.Absolute, out Uri? uri)               &&
                    string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                    uri.IsLoopback                                                                   &&
                    uri.Port == await _listener.GetEmbeddedServerPortAsync(context.CancellationToken);
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
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Most applications (except Windows UWP applications) are multi-instanced. As such, any protocol activation
            // triggered by launching one of the URI schemes associated with the application will create a new instance,
            // different from the one that initially started the authentication flow. To deal with that without having to
            // share persistent state between instances, OpenIddict stores the identifier of the instance that starts the
            // authentication process and uses it when handling the callback to determine whether the protocol activation
            // should be redirected to a different instance using inter-process communication.
            context.StateTokenPrincipal.SetClaim(Claims.Private.InstanceId, _options.CurrentValue.InstanceIdentifier);

            return ValueTask.CompletedTask;
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
            ArgumentNullException.ThrowIfNull(context);

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

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for inferring the base URI from the client URI set in the options.
    /// Note: this handler is not used when the user session is not interactive.
    /// </summary>
    public sealed class InferLogoutBaseUriFromClientUri : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireInteractiveSession>()
                .UseSingletonHandler<InferLogoutBaseUriFromClientUri>()
                .SetOrder(ValidateSignOutDemand.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            context.BaseUri ??= context.Options.ClientUri;

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the listening port of the
    /// embedded web server to the post_logout_redirect_uri, if applicable.
    /// Note: this handler is not used when the user session is not interactive.
    /// </summary>
    public sealed class AttachDynamicPortToPostLogoutRedirectUri : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        private readonly OpenIddictClientSystemIntegrationHttpListener _listener;

        public AttachDynamicPortToPostLogoutRedirectUri(OpenIddictClientSystemIntegrationHttpListener listener)
            => _listener = listener ?? throw new ArgumentNullException(nameof(listener));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireInteractiveSession>()
                .AddFilter<RequireEmbeddedWebServerEnabled>()
                // Note: only apply the dynamic port replacement logic if the callback request
                // is going to be received by the system browser to ensure it doesn't apply to
                // sign-out demands handled via a web authentication broker are not affected.
                .AddFilter<RequireSystemBrowser>()
                .UseSingletonHandler<AttachDynamicPortToPostLogoutRedirectUri>()
                .SetOrder(AttachPostLogoutRedirectUri.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignOutContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // If the post_logout_redirect_uri uses a loopback host/IP as the authority and doesn't include a non-default port,
            // determine whether the embedded web server is running: if so, override the port in the post_logout_redirect_uri
            // by the port used by the embedded web server (guaranteed to be running if a value is returned).
            if (!string.IsNullOrEmpty(context.PostLogoutRedirectUri)                             &&
                Uri.TryCreate(context.PostLogoutRedirectUri, UriKind.Absolute, out Uri? uri)     &&
                string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                uri.IsLoopback                                                                   &&
                uri.IsDefaultPort                                                                &&
                await _listener.GetEmbeddedServerPortAsync(context.CancellationToken) is int port)
            {
                var builder = new UriBuilder(context.PostLogoutRedirectUri)
                {
                    Port = port
                };

                context.PostLogoutRedirectUri = builder.Uri.AbsoluteUri;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for storing the identifier of the current instance in the state token.
    /// Note: this handler is not used when the user session is not interactive.
    /// </summary>
    public sealed class AttachLogoutInstanceIdentifier : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> _options;

        public AttachLogoutInstanceIdentifier(IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireInteractiveSession>()
                .AddFilter<RequireLogoutStateTokenGenerated>()
                .UseSingletonHandler<AttachLogoutInstanceIdentifier>()
                .SetOrder(PrepareLogoutStateTokenPrincipal.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Most applications (except Windows UWP applications) are multi-instanced. As such, any protocol activation
            // triggered by launching one of the URI schemes associated with the application will create a new instance,
            // different from the one that initially started the logout flow. To deal with that without having to share
            // persistent state between instances, OpenIddict stores the identifier of the instance that starts the
            // logout process and uses it when handling the callback to determine whether the protocol activation
            // should be redirected to a different instance using inter-process communication.
            context.StateTokenPrincipal.SetClaim(Claims.Private.InstanceId, _options.CurrentValue.InstanceIdentifier);

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for asking the marshal to track the logout operation.
    /// Note: this handler is not used when the user session is not interactive.
    /// </summary>
    public sealed class TrackLogoutOperation : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        private readonly OpenIddictClientSystemIntegrationMarshal _marshal;

        public TrackLogoutOperation(OpenIddictClientSystemIntegrationMarshal marshal)
            => _marshal = marshal ?? throw new ArgumentNullException(nameof(marshal));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireInteractiveSession>()
                .AddFilter<RequireLogoutStateTokenGenerated>()
                .UseSingletonHandler<TrackLogoutOperation>()
                .SetOrder(100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

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

            return ValueTask.CompletedTask;
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
            ArgumentNullException.ThrowIfNull(context);

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
                return ValueTask.CompletedTask;
            }

            return ValueTask.CompletedTask;
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
            ArgumentNullException.ThrowIfNull(context);

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

            return ValueTask.CompletedTask;
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
            ArgumentNullException.ThrowIfNull(context);

            // This handler only applies to HTTP listener requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpListenerContext()?.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0390));

            // Prevent the response from being cached.
            response.Headers[Headers.CacheControl] = "no-store";
            response.Headers[Headers.Pragma] = "no-cache";
            response.Headers[Headers.Expires] = "Thu, 01 Jan 1970 00:00:00 GMT";

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for marking OpenID Connect
    /// responses returned via protocol activations as processed.
    /// </summary>
    public sealed class ProcessProtocolActivationResponse<TContext> : IOpenIddictClientHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireProtocolActivation>()
                .UseSingletonHandler<ProcessProtocolActivationResponse<TContext>>()
                .SetOrder(ProcessPlatformCallbackResponse<TContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // For both protocol activations (initial or redirected) and web-view-like results,
            // no proper response can be generated and eventually displayed to the user. In this
            // case, simply stop processing the response and mark the request as fully handled.
            //
            // Note: this logic applies to both successful and errored responses.

            context.HandleRequest();
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for marking OpenID Connect responses returned via a platform callback.
    /// </summary>
    public sealed class ProcessPlatformCallbackResponse<TContext> : IOpenIddictClientHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequirePlatformCallback>()
                .UseSingletonHandler<ProcessPlatformCallbackResponse<TContext>>()
                .SetOrder(int.MaxValue)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // For both protocol activations (initial or redirected) and web-view-like results,
            // no proper response can be generated and eventually displayed to the user. In this
            // case, simply stop processing the response and mark the request as fully handled.
            //
            // Note: this logic applies to both successful and errored responses.

            context.HandleRequest();
            return ValueTask.CompletedTask;
        }
    }
}
