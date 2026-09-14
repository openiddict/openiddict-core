/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text;
using Owin;
using static OpenIddict.Server.Owin.OpenIddictServerOwinConstants;

namespace OpenIddict.Server.Owin;

public static partial class OpenIddictServerOwinHandlers
{
    /// <summary>
    /// Contains the OWIN handlers implementing OpenID Connect Front-Channel Logout 1.0 and Session Management 1.0.
    /// </summary>
    public static class Logout
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Check session iframe request processing:
             */
            ProcessCheckSessionIframeRequest.Descriptor,
            ProcessCheckSessionIframeErrorResponse.Descriptor,

            /*
             * Sign-in/sign-out processing:
             */
            AttachBrowserState.Descriptor,
            RemoveBrowserState.Descriptor,

            /*
             * End-session response processing:
             */
            ProcessFrontchannelLogoutResponse.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for serving the check session iframe defined by OpenID Connect Session Management 1.0.
        /// </summary>
        public sealed class ProcessCheckSessionIframeRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessCheckSessionIframeRequest>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.EndpointType is not OpenIddictServerEndpointType.CheckSessionIframe || context.IsRejected)
                {
                    return;
                }

                var request = context.Transaction.GetOwinRequest()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

                if (!string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(request.Method, "HEAD", StringComparison.OrdinalIgnoreCase))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2084),
                        uri: SR.FormatID8000(SR.ID2084));

                    return;
                }

                var nonce = OpenIddictServerHelpers.CreateContentSecurityPolicyNonce();
                var content = Encoding.UTF8.GetBytes(OpenIddictServerHelpers.CreateCheckSessionIframePage(
                    context.Options.BrowserStateCookieName, nonce));

                var response = request.Context.Response;
                response.StatusCode = 200;
                response.ContentType = "text/html;charset=UTF-8";
                response.ContentLength = content.Length;
                response.Headers[Headers.CacheControl] = "no-store";
                response.Headers[Headers.Pragma] = "no-cache";
                response.Headers["Content-Security-Policy"] = $"default-src 'none'; script-src 'nonce-{nonce}'";

                if (!string.Equals(request.Method, "HEAD", StringComparison.OrdinalIgnoreCase))
                {
                    await response.Body.WriteAsync(content, 0, content.Length, context.CancellationToken);
                }

                context.HandleRequest();
            }
        }

        /// <summary>
        /// Contains the logic responsible for returning errors (e.g transport security errors) for check session iframe requests.
        /// </summary>
        public sealed class ProcessCheckSessionIframeErrorResponse : IOpenIddictServerHandler<ProcessErrorContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessErrorContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessCheckSessionIframeErrorResponse>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessErrorContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.EndpointType is not OpenIddictServerEndpointType.CheckSessionIframe || context.IsRequestHandled)
                {
                    return;
                }

                var response = context.Transaction.GetOwinRequest()?.Context.Response
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

                var content = Encoding.UTF8.GetBytes(context.Error ?? Errors.InvalidRequest);

                response.StatusCode = 400;
                response.ContentType = "text/plain;charset=UTF-8";
                response.ContentLength = content.Length;
                response.Headers[Headers.CacheControl] = "no-store";

                await response.Body.WriteAsync(content, 0, content.Length, context.CancellationToken);

                context.HandleRequest();
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the OP browser state (stored in a cookie readable by the
        /// check session iframe) to successful authorization responses when session management is enabled.
        /// The browser state is bound to the subject and is renewed when a different user signs in.
        /// </summary>
        public sealed class AttachBrowserState : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<AttachBrowserState>()
                    .SetOrder(AttachSignInParameters.Descriptor.Order + 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessSignInContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!context.Options.EnableSessionManagement ||
                    context.EndpointType is not OpenIddictServerEndpointType.Authorization ||
                    context.Principal is not { Identity.IsAuthenticated: true } principal)
                {
                    return ValueTask.CompletedTask;
                }

                var request = context.Transaction.GetOwinRequest()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

                context.Transaction.BrowserState = OpenIddictServerOwinHelpers.EnsureBrowserState(
                    request.Context, context.Options, principal.GetClaim(Claims.Subject));

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for removing the OP browser state cookie when the user is signed out.
        /// </summary>
        public sealed class RemoveBrowserState : IOpenIddictServerHandler<ProcessSignOutContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<RemoveBrowserState>()
                    .SetOrder(AttachCustomSignOutParameters.Descriptor.Order + 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessSignOutContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!context.Options.EnableSessionManagement)
                {
                    return ValueTask.CompletedTask;
                }

                var request = context.Transaction.GetOwinRequest()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

                OpenIddictServerOwinHelpers.RemoveBrowserState(request.Context, context.Options);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rendering the front-channel logout iframes before redirecting the user agent,
        /// as defined by OpenID Connect Front-Channel Logout 1.0. Note: this handler is only used when front-channel logout
        /// URIs were resolved for the terminated session.
        /// </summary>
        public sealed class ProcessFrontchannelLogoutResponse : IOpenIddictServerHandler<ApplyEndSessionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyEndSessionResponseContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessFrontchannelLogoutResponse>()
                    .SetOrder(Session.ProcessQueryResponse.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ApplyEndSessionResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.FrontchannelLogoutUris.Count is 0 || !string.IsNullOrEmpty(context.Response.Error) ||
                    !string.IsNullOrEmpty(context.Response.RequestUri))
                {
                    return;
                }

                var response = context.Transaction.GetOwinRequest()?.Context.Response
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

                string? location = null;

                if (!string.IsNullOrEmpty(context.PostLogoutRedirectUri))
                {
                    location = context.PostLogoutRedirectUri;

                    foreach (var (key, value) in
                        from parameter in context.Response.GetParameters()
                        let values = (ImmutableArray<string?>?) parameter.Value
                        where values is not null
                        from value in values.GetValueOrDefault()
                        where !string.IsNullOrEmpty(value)
                        select (parameter.Key, Value: value))
                    {
                        location = WebUtilities.AddQueryString(location, key, value);
                    }
                }

                else if (context.Transaction.GetProperty<AuthenticationProperties>(
                    typeof(AuthenticationProperties).FullName!) is { RedirectUri.Length: > 0 } properties)
                {
                    location = properties.RedirectUri;
                }

                var nonce = OpenIddictServerHelpers.CreateContentSecurityPolicyNonce();
                var content = Encoding.UTF8.GetBytes(OpenIddictServerHelpers.CreateFrontchannelLogoutPage(
                    context.FrontchannelLogoutUris, location, nonce));

                response.StatusCode = 200;
                response.ContentType = "text/html;charset=UTF-8";
                response.ContentLength = content.Length;
                response.Headers[Headers.CacheControl] = "no-store";
                response.Headers[Headers.Pragma] = "no-cache";
                response.Headers["Content-Security-Policy"] = OpenIddictServerHelpers
                    .CreateFrontchannelLogoutContentSecurityPolicy(context.FrontchannelLogoutUris, nonce);

                await response.Body.WriteAsync(content, 0, content.Length, context.CancellationToken);

                context.HandleRequest();
            }
        }
    }
}
