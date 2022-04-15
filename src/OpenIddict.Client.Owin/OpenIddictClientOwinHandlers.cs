/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Owin;
using static OpenIddict.Client.Owin.OpenIddictClientOwinConstants;
using Properties = OpenIddict.Client.Owin.OpenIddictClientOwinConstants.Properties;

namespace OpenIddict.Client.Owin;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictClientOwinHandlers
{
    public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
        /*
         * Top-level request processing:
         */
        InferEndpointType.Descriptor,

        /*
         * Authentication processing:
         */
        ValidateCorrelationCookie.Descriptor,

        /*
         * Challenge processing:
         */
        GenerateCorrelationCookie.Descriptor,
        ResolveHostChallengeParameters.Descriptor)
        .AddRange(Authentication.DefaultHandlers);

    /// <summary>
    /// Contains the logic responsible for inferring the endpoint type from the request address.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class InferEndpointType : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<InferEndpointType>()
                // Note: this handler must be invoked before any other handler,
                // including the built-in handlers defined in OpenIddict.Client.
                .SetOrder(int.MinValue + 50_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context!!)
        {
            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            context.EndpointType =
                Matches(request, context.Options.RedirectionEndpointUris) ? OpenIddictClientEndpointType.Redirection :
                                                                            OpenIddictClientEndpointType.Unknown;

            return default;

            static bool Matches(IOwinRequest request, IReadOnlyList<Uri> addresses)
            {
                for (var index = 0; index < addresses.Count; index++)
                {
                    var address = addresses[index];
                    if (address.IsAbsoluteUri)
                    {
                        // If the request host is not available (e.g because HTTP/1.0 was used), ignore absolute URLs.
                        if (string.IsNullOrEmpty(request.Host.Value))
                        {
                            continue;
                        }

                        // Create a Uri instance using the request scheme and raw host and compare the two base addresses.
                        if (!Uri.TryCreate(request.Scheme + Uri.SchemeDelimiter + request.Host, UriKind.Absolute, out Uri? uri) ||
                            !uri.IsWellFormedOriginalString() || uri.Port != address.Port ||
                            !string.Equals(uri.Scheme, address.Scheme, StringComparison.OrdinalIgnoreCase) ||
                            !string.Equals(uri.Host, address.Host, StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        var path = PathString.FromUriComponent(address);
                        if (AreEquivalent(path, request.PathBase + request.Path))
                        {
                            return true;
                        }
                    }

                    else if (address.OriginalString.StartsWith("/", StringComparison.OrdinalIgnoreCase))
                    {
                        var path = new PathString(address.OriginalString);
                        if (AreEquivalent(path, request.Path))
                        {
                            return true;
                        }
                    }
                }

                return false;

                // ASP.NET MVC's routing system ignores trailing slashes when determining
                // whether the request path matches a registered route, which is not the case
                // with PathString, that treats /connect/token and /connect/token/ as different
                // addresses. To mitigate this inconsistency, a manual check is used here.
                static bool AreEquivalent(PathString left, PathString right)
                    => left.Equals(right, StringComparison.OrdinalIgnoreCase) ||
                       left.Equals(right + new PathString("/"), StringComparison.OrdinalIgnoreCase) ||
                       right.Equals(left + new PathString("/"), StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from GET or POST HTTP requests.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class ExtractGetOrPostRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ExtractGetOrPostRequest<TContext>>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context!!)
        {
            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            if (string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase))
            {
                context.Transaction.Request = new OpenIddictRequest(request.Query);
            }

            else if (string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
            {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrEmpty(request.ContentType))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6138), Headers.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2081(Headers.ContentType),
                        uri: SR.FormatID8000(SR.ID2081));

                    return;
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6139), Headers.ContentType, request.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2082(Headers.ContentType),
                        uri: SR.FormatID8000(SR.ID2082));

                    return;
                }

                context.Transaction.Request = new OpenIddictRequest(await request.ReadFormAsync());
            }

            else
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6137), request.Method);

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2084),
                    uri: SR.FormatID8000(SR.ID2084));

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the correlation cookie that serves as a CSRF protection.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class ValidateCorrelationCookie : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientOwinOptions> _options;

        public ValidateCorrelationCookie(IOptionsMonitor<OpenIddictClientOwinOptions> options!!)
            => _options = options;

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireOwinRequest>()
                .AddFilter<RequireStateTokenValidated>()
                .UseSingletonHandler<ValidateCorrelationCookie>()
                .SetOrder(ValidateStateToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context!!)
        {
            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // This handler only applies to OWIN requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Resolve the request forgery protection from the state token principal.
            // If the claim cannot be found, this means the protection was disabled
            // using a custom event handler. In this case, bypass the validation.
            var claim = context.StateTokenPrincipal.GetClaim(Claims.RequestForgeryProtection);
            if (string.IsNullOrEmpty(claim))
            {
                return default;
            }

            // Resolve the cookie manager and the cookie options from the OWIN integration options.
            var (manager, options) = (
                _options.CurrentValue.CookieManager,
                _options.CurrentValue.CookieOptions);

            // Compute the name of the cookie name based on the prefix set in the options
            // and the random request forgery protection claim restored from the state.
            var name = new StringBuilder(_options.CurrentValue.CookieName)
                .Append(Separators.Dot)
                .Append(claim)
                .ToString();

            // Try to find the cookie matching the request forgery protection stored in the state.
            //
            // If the cookie cannot be found, this may indicate that the authorization response
            // is unsolicited and potentially malicious. This may also be caused by an unadequate
            // same-site configuration. In any case, the authentication demand MUST be rejected
            // as it's impossible to ensure it's not a session fixation attack without the cookie.
            var value = manager.GetRequestCookie(request.Context, name);
            if (string.IsNullOrEmpty(value) || !string.Equals(value, "v1", StringComparison.Ordinal))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2129),
                    uri: SR.FormatID8000(SR.ID2129));

                return default;
            }

            // Return a response header asking the browser to delete the state cookie.
            //
            // Note: when deleting a cookie, the same options used when creating it MUST be specified.
            manager.DeleteCookie(request.Context, name, new CookieOptions
            {
                Domain = options.Domain,
                HttpOnly = options.HttpOnly,
                Path = options.Path,
                SameSite = options.SameSite,
                Secure = options.Secure
            });

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the additional challenge parameters stored in the ASP.NET
    /// Core authentication properties specified by the application that triggered the challenge operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class ResolveHostChallengeParameters : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ResolveHostChallengeParameters>()
                .SetOrder(ValidateChallengeDemand.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context!!)
        {
            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is null)
            {
                return default;
            }

            // If an issuer was explicitly set, update the challenge context to use it.
            if (properties.Dictionary.TryGetValue(Properties.Issuer, out string? issuer) && !string.IsNullOrEmpty(issuer))
            {
                // Ensure the issuer set by the application is a valid absolute URI.
                if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0306));
                }

                context.Issuer = uri;
            }

            // If a return URL was specified, use it as the target_link_uri claim.
            if (!string.IsNullOrEmpty(properties.RedirectUri))
            {
                context.TargetLinkUri = properties.RedirectUri;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for creating a correlation cookie that serves as a CSRF countermeasure.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class GenerateCorrelationCookie : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientOwinOptions> _options;

        public GenerateCorrelationCookie(IOptionsMonitor<OpenIddictClientOwinOptions> options!!)
            => _options = options;

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireOwinRequest>()
                .AddFilter<RequireStateTokenGenerated>()
                .UseSingletonHandler<GenerateCorrelationCookie>()
                .SetOrder(AttachChallengeParameters.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context!!)
        {
            // Note: using a correlation cookie serves as an antiforgery protection as the request will
            // always be rejected if a cookie corresponding to the request forgery protection claim
            // persisted in the state token cannot be found. This protection is considered essential
            // in OpenIddict and cannot be disabled via the options. Applications that prefer implementing
            // a different protection strategy can set the request forgery protection claim to null or
            // remove this handler from the handlers list and add a custom one using a different approach.

            if (string.IsNullOrEmpty(context.RequestForgeryProtection))
            {
                return default;
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));
            Debug.Assert(!string.IsNullOrEmpty(context.StateToken), SR.GetResourceString(SR.ID4010));

            // This handler only applies to OWIN requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Compute a collision-resistant and hard-to-guess cookie name based on the prefix set
            // in the options and the random request forgery protection claim generated earlier.
            var name = new StringBuilder(_options.CurrentValue.CookieName)
                .Append(Separators.Dot)
                .Append(context.RequestForgeryProtection)
                .ToString();

            // Resolve the cookie manager and the cookie options from the OWIN integration options.
            var (manager, options) = (
                _options.CurrentValue.CookieManager,
                _options.CurrentValue.CookieOptions);

            // Add the correlation cookie to the response headers.
            manager.AppendResponseCookie(response.Context, name, "v1", new CookieOptions
            {
                Domain = options.Domain,
                HttpOnly = options.HttpOnly,
                Path = options.Path,
                SameSite = options.SameSite,
                Secure = options.Secure,

                // Use the expiration date of the state token principal
                // as the expiration date of the correlation cookie.
                Expires = context.StateTokenPrincipal.GetExpirationDate()?.UtcDateTime

            });

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for enabling the pass-through mode for the received request.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class EnablePassthroughMode<TContext, TFilter> : IOpenIddictClientHandler<TContext>
        where TContext : BaseRequestContext
        where TFilter : IOpenIddictClientHandlerFilter<TContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .AddFilter<TFilter>()
                .UseSingletonHandler<EnablePassthroughMode<TContext, TFilter>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context!!)
        {
            context.SkipRequest();

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching an appropriate HTTP status code.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class AttachHttpResponseCode<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<AttachHttpResponseCode<TContext>>()
                .SetOrder(100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context!!)
        {
            // This handler only applies to OWIN requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

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
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class AttachCacheControlHeader<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<AttachCacheControlHeader<TContext>>()
                .SetOrder(AttachHttpResponseCode<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context!!)
        {
            // This handler only applies to OWIN requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Prevent the response from being cached.
            response.Headers[Headers.CacheControl] = "no-store";
            response.Headers[Headers.Pragma] = "no-cache";
            response.Headers[Headers.Expires] = "Thu, 01 Jan 1970 00:00:00 GMT";

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing OpenID Connect responses that must be handled by another
    /// middleware in the pipeline at a later stage (e.g an ASP.NET MVC action or a NancyFX module).
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class ProcessPassthroughErrorResponse<TContext, TFilter> : IOpenIddictClientHandler<TContext>
        where TContext : BaseRequestContext
        where TFilter : IOpenIddictClientHandlerFilter<TContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .AddFilter<RequireErrorPassthroughEnabled>()
                .AddFilter<TFilter>()
                .UseSingletonHandler<ProcessPassthroughErrorResponse<TContext, TFilter>>()
                .SetOrder(100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context!!)
        {
            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            if (string.IsNullOrEmpty(context.Transaction.Response.Error))
            {
                return default;
            }

            context.SkipRequest();

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing context responses that must be returned as plain-text.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class ProcessLocalErrorResponse<TContext> : IOpenIddictClientHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ProcessLocalErrorResponse<TContext>>()
                .SetOrder(ProcessPassthroughErrorResponse<TContext, IOpenIddictClientHandlerFilter<TContext>>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context!!)
        {
            // This handler only applies to OWIN requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            if (string.IsNullOrEmpty(context.Transaction.Response.Error))
            {
                return;
            }

            // Don't return the state originally sent by the client application.
            context.Transaction.Response.State = null;

            context.Logger.LogInformation(SR.GetResourceString(SR.ID6143), context.Transaction.Response);

            using var stream = new MemoryStream();
            using var writer = new StreamWriter(stream);

            foreach (var parameter in context.Transaction.Response.GetParameters())
            {
                // Ignore null or empty parameters, including JSON
                // objects that can't be represented as strings.
                var value = (string?) parameter.Value;
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                writer.Write(parameter.Key);
                writer.Write(':');
                writer.Write(value);
                writer.WriteLine();
            }

            writer.Flush();

            response.ContentLength = stream.Length;
            response.ContentType = "text/plain;charset=UTF-8";

            stream.Seek(offset: 0, loc: SeekOrigin.Begin);
            await stream.CopyToAsync(response.Body, 4096, response.Context.Request.CallCancelled);

            context.HandleRequest();
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing OpenID Connect responses that don't specify any parameter.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class ProcessEmptyResponse<TContext> : IOpenIddictClientHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ProcessEmptyResponse<TContext>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context!!)
        {
            context.Logger.LogInformation(SR.GetResourceString(SR.ID6145));
            context.HandleRequest();

            return default;
        }
    }
}
