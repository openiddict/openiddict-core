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
using System.Text.Json;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Properties = OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Properties;

#if SUPPORTS_JSON_NODES
using System.Text.Json.Nodes;
#endif

namespace OpenIddict.Client.AspNetCore;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictClientAspNetCoreHandlers
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
        ValidateEndpointUri.Descriptor,

        /*
         * Challenge processing:
         */
        ResolveHostChallengeParameters.Descriptor,
        GenerateLoginCorrelationCookie.Descriptor,

        /*
         * Sign-out processing:
         */
        ResolveHostSignOutParameters.Descriptor,
        GenerateLogoutCorrelationCookie.Descriptor)
        .AddRange(Authentication.DefaultHandlers)
        .AddRange(Session.DefaultHandlers);

    /// <summary>
    /// Contains the logic responsible for inferring the endpoint type from the request address.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public class InferEndpointType : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<InferEndpointType>()
                .SetOrder(int.MinValue + 50_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            context.EndpointType =
                Matches(request, context.Options.PostLogoutRedirectionEndpointUris) ? OpenIddictClientEndpointType.PostLogoutRedirection :
                Matches(request, context.Options.RedirectionEndpointUris)           ? OpenIddictClientEndpointType.Redirection :
                                                                                      OpenIddictClientEndpointType.Unknown;

            return default;

            static bool Matches(HttpRequest request, IReadOnlyList<Uri> addresses)
            {
                for (var index = 0; index < addresses.Count; index++)
                {
                    var address = addresses[index];
                    if (address.IsAbsoluteUri)
                    {
                        // If the request host is not available (e.g because HTTP/1.0 was used), ignore absolute URLs.
                        if (!request.Host.HasValue)
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

                // ASP.NET Core's routing system ignores trailing slashes when determining
                // whether the request path matches a registered route, which is not the case
                // with PathString, that treats /connect/token and /connect/token/ as different
                // addresses. To mitigate this inconsistency, a manual check is used here.
                static bool AreEquivalent(PathString left, PathString right)
                    => left.Equals(right, StringComparison.OrdinalIgnoreCase) ||
                       left.Equals(right + "/", StringComparison.OrdinalIgnoreCase) ||
                       right.Equals(left + "/", StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from GET or POST HTTP requests.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public class ExtractGetOrPostRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ExtractGetOrPostRequest<TContext>>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            if (HttpMethods.IsGet(request.Method))
            {
                context.Transaction.Request = new OpenIddictRequest(request.Query);
            }

            else if (HttpMethods.IsPost(request.Method))
            {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrEmpty(request.ContentType))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6138), HeaderNames.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2081(HeaderNames.ContentType),
                        uri: SR.FormatID8000(SR.ID2081));

                    return;
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6139), HeaderNames.ContentType, request.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2082(HeaderNames.ContentType),
                        uri: SR.FormatID8000(SR.ID2082));

                    return;
                }

                context.Transaction.Request = new OpenIddictRequest(await request.ReadFormAsync(request.HttpContext.RequestAborted));
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
    /// Contains the logic responsible for validating the correlation cookie that serves as a protection
    /// against state token injection, forged requests, denial of service and session fixation attacks.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public class ValidateCorrelationCookie : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientAspNetCoreOptions> _options;

        public ValidateCorrelationCookie(IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireHttpRequest>()
                .AddFilter<RequireStateTokenValidated>()
                .UseSingletonHandler<ValidateCorrelationCookie>()
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

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // Resolve the request forgery protection from the state token principal.
            var identifier = context.StateTokenPrincipal.GetClaim(Claims.RequestForgeryProtection);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0339));
            }

            // Resolve the cookie builder from the OWIN integration options.
            var builder = _options.CurrentValue.CookieBuilder;

            // Compute the name of the cookie name based on the prefix set in the options
            // and the random request forgery protection claim restored from the state.
            var name = new StringBuilder(builder.Name)
                .Append(Separators.Dot)
                .Append(identifier)
                .ToString();

            // Try to find the cookie matching the request forgery protection stored in the state.
            // The correlation cookie serves as a binding mechanism ensuring that a state token
            // stolen from an authorization response with the other parameters cannot be validly
            // used without sending the matching correlation identifier used as the cookie name.
            //
            // If the cookie cannot be found, this may indicate that the authorization response
            // is unsolicited and potentially malicious or be caused by an invalid or unadequate
            // same-site configuration.
            //
            // In any case, the authentication demand MUST be rejected as it's impossible to ensure
            // it's not an injection or session fixation attack without the correlation cookie.
            var value = request.Cookies[name];
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
            request.HttpContext.Response.Cookies.Delete(name, builder.Build(request.HttpContext));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for comparing the current request URL to the expected URL stored in the state token.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public class ValidateEndpointUri : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireHttpRequest>()
                .AddFilter<RequireStateTokenValidated>()
                .UseSingletonHandler<ValidateEndpointUri>()
                .SetOrder(ValidateCorrelationCookie.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // Resolve the endpoint type allowed to be used with the state token.
            if (!Enum.TryParse(context.StateTokenPrincipal.GetClaim(Claims.Private.EndpointType),
                ignoreCase: true, out OpenIddictClientEndpointType type))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0340));
            }

            // Resolve the endpoint URI from either the redirect_uri or post_logout_redirect_uri
            // depending on the type of endpoint meant to be used with the specified state token.
            var value = type switch
            {
                OpenIddictClientEndpointType.PostLogoutRedirection =>
                    context.StateTokenPrincipal.GetClaim(Claims.Private.PostLogoutRedirectUri),

                OpenIddictClientEndpointType.Redirection =>
                    context.StateTokenPrincipal.GetClaim(Claims.Private.RedirectUri),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0340))
            };

            // If the endpoint URI cannot be resolved, this likely means the authorization or
            // logout request was sent without a redirect_uri/post_logout_redirect_uri attached.
            if (string.IsNullOrEmpty(value))
            {
                return default;
            }

            // Compute the absolute URL of the current request without the query string.
            var uri = new Uri(request.Scheme + Uri.SchemeDelimiter + request.Host +
                request.PathBase + request.Path, UriKind.Absolute);

            // Compare the current HTTP request address to the original endpoint URI. If the two don't
            // match, this may indicate a mix-up attack. While the authorization server is expected to
            // abort the authorization flow by rejecting the token request that may be eventually sent
            // with the original endpoint URI, many servers are known to incorrectly implement this
            // endpoint URI validation logic. This check also offers limited protection as it cannot
            // prevent the authorization code from being leaked to a malicious authorization server.
            // By comparing the endpoint URI directly in the client, a first layer of protection is
            // provided independently of whether the authorization server will enforce this check.
            //
            // See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-19#section-4.4.2.2
            // for more information.
            var address = new Uri(value, UriKind.Absolute);
            if (uri != new UriBuilder(address) { Query = null }.Uri)
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2138),
                    uri: SR.FormatID8000(SR.ID2138));

                return default;
            }

            // Ensure all the query string parameters that were part of the original endpoint URI
            // are present in the current request (parameters that were not part of the original
            // endpoint URI are assumed to be authorization response parameters and are ignored).
            if (!string.IsNullOrEmpty(address.Query) && QueryHelpers.ParseQuery(address.Query)
                .Any(parameter => request.Query[parameter.Key] != parameter.Value))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2138),
                    uri: SR.FormatID8000(SR.ID2138));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the additional challenge parameters stored in the ASP.NET
    /// Core authentication properties specified by the application that triggered the challenge operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public class ResolveHostChallengeParameters : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ResolveHostChallengeParameters>()
                .SetOrder(ValidateChallengeDemand.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is null)
            {
                return default;
            }

            // If an issuer was explicitly set, update the challenge context to use it.
            if (properties.Items.TryGetValue(Properties.Issuer, out string? issuer) && !string.IsNullOrEmpty(issuer))
            {
                // Ensure the issuer set by the application is a valid absolute URI.
                if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0306));
                }

                context.Issuer = uri;
            }

            // If a provider name was explicitly set, update the challenge context to use it.
            if (properties.Items.TryGetValue(Properties.ProviderName, out string? provider) &&
                !string.IsNullOrEmpty(provider))
            {
                context.ProviderName = provider;
            }

            // If a return URL was specified, use it as the target_link_uri claim.
            if (!string.IsNullOrEmpty(properties.RedirectUri))
            {
                context.TargetLinkUri = properties.RedirectUri;
            }

            // If an identity token hint was specified, attach it to the context.
            if (properties.Items.TryGetValue(Properties.IdentityTokenHint, out string? token) &&
                !string.IsNullOrEmpty(token))
            {
                context.IdentityTokenHint = token;
            }

            // If a login hint was specified, attach it to the context.
            if (properties.Items.TryGetValue(Properties.LoginHint, out string? hint) &&
                !string.IsNullOrEmpty(hint))
            {
                context.LoginHint = hint;
            }

            // Preserve the host properties in the principal.
            if (properties.Items.Count is not 0)
            {
                context.Principal.SetClaim(Claims.Private.HostProperties, properties.Items);
            }

            foreach (var parameter in properties.Parameters)
            {
                context.Parameters[parameter.Key] = parameter.Value switch
                {
                    OpenIddictParameter value => value,
                    JsonElement         value => new OpenIddictParameter(value),
                    bool                value => new OpenIddictParameter(value),
                    int                 value => new OpenIddictParameter(value),
                    long                value => new OpenIddictParameter(value),
                    string              value => new OpenIddictParameter(value),
                    string[]            value => new OpenIddictParameter(value),

#if SUPPORTS_JSON_NODES
                    JsonNode            value => new OpenIddictParameter(value),
#endif
                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0115))
                };
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for creating a correlation cookie that serves as a
    /// protection against state token injection, forged requests and session fixation attacks.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public class GenerateLoginCorrelationCookie : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientAspNetCoreOptions> _options;

        public GenerateLoginCorrelationCookie(IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireHttpRequest>()
                .AddFilter<RequireInteractiveGrantType>()
                .AddFilter<RequireLoginStateTokenGenerated>()
                .UseSingletonHandler<GenerateLoginCorrelationCookie>()
                .SetOrder(AttachChallengeParameters.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: using a correlation cookie serves as an injection/antiforgery protection as the request
            // will always be rejected if a cookie corresponding to the request forgery protection claim
            // persisted in the state token cannot be found. This protection is considered essential
            // in OpenIddict and cannot be disabled via the options. Applications that prefer implementing
            // a different protection strategy can remove this handler from the handlers list and add
            // a custom one using a different approach (e.g by storing the value in the session state).

            if (string.IsNullOrEmpty(context.RequestForgeryProtection))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0343));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // Resolve the cookie builder from the OWIN integration options.
            var builder = _options.CurrentValue.CookieBuilder;

            // Unless a value was explicitly set in the options, use the expiration date
            // of the state token principal as the expiration date of the correlation cookie.
            var options = builder.Build(response.HttpContext);
            options.Expires ??= context.StateTokenPrincipal.GetExpirationDate();

            // Compute a collision-resistant and hard-to-guess cookie name based on the prefix set
            // in the options and the random request forgery protection claim generated earlier.
            var name = new StringBuilder(builder.Name)
                .Append(Separators.Dot)
                .Append(context.RequestForgeryProtection)
                .ToString();

            // Add the correlation cookie to the response headers.
            response.Cookies.Append(name, "v1", options);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the additional sign-out parameters stored in the ASP.NET
    /// Core authentication properties specified by the application that triggered the sign-out operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public class ResolveHostSignOutParameters : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ResolveHostSignOutParameters>()
                .SetOrder(ValidateSignOutDemand.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is null)
            {
                return default;
            }

            // If an issuer was explicitly set, update the sign-out context to use it.
            if (properties.Items.TryGetValue(Properties.Issuer, out string? issuer) && !string.IsNullOrEmpty(issuer))
            {
                // Ensure the issuer set by the application is a valid absolute URI.
                if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0306));
                }

                context.Issuer = uri;
            }

            // If a provider name was explicitly set, update the sign-out context to use it.
            if (properties.Items.TryGetValue(Properties.ProviderName, out string? provider) &&
                !string.IsNullOrEmpty(provider))
            {
                context.ProviderName = provider;
            }

            // If a return URL was specified, use it as the target_link_uri claim.
            if (!string.IsNullOrEmpty(properties.RedirectUri))
            {
                context.TargetLinkUri = properties.RedirectUri;
            }

            // If an identity token hint was specified, attach it to the context.
            if (properties.Items.TryGetValue(Properties.IdentityTokenHint, out string? token) &&
                !string.IsNullOrEmpty(token))
            {
                context.IdentityTokenHint = token;
            }

            // If a login hint was specified, attach it to the context.
            if (properties.Items.TryGetValue(Properties.LoginHint, out string? hint) &&
                !string.IsNullOrEmpty(hint))
            {
                context.LoginHint = hint;
            }

            // Preserve the host properties in the principal.
            if (properties.Items.Count is not 0)
            {
                context.Principal.SetClaim(Claims.Private.HostProperties, properties.Items);
            }

            foreach (var parameter in properties.Parameters)
            {
                context.Parameters[parameter.Key] = parameter.Value switch
                {
                    OpenIddictParameter value => value,
                    JsonElement value         => new OpenIddictParameter(value),
                    bool value                => new OpenIddictParameter(value),
                    int value                 => new OpenIddictParameter(value),
                    long value                => new OpenIddictParameter(value),
                    string value              => new OpenIddictParameter(value),
                    string[] value            => new OpenIddictParameter(value),

#if SUPPORTS_JSON_NODES
                    JsonNode            value => new OpenIddictParameter(value),
#endif
                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0115))
                };
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for creating a correlation cookie that serves as a
    /// protection against state token injection, forged requests and denial of service attacks.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public class GenerateLogoutCorrelationCookie : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientAspNetCoreOptions> _options;

        public GenerateLogoutCorrelationCookie(IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireHttpRequest>()
                .AddFilter<RequireLogoutStateTokenGenerated>()
                .UseSingletonHandler<GenerateLogoutCorrelationCookie>()
                .SetOrder(AttachChallengeParameters.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: using a correlation cookie serves as an injection/antiforgery protection as the request
            // will always be rejected if a cookie corresponding to the request forgery protection claim
            // persisted in the state token cannot be found. This protection is considered essential
            // in OpenIddict and cannot be disabled via the options. Applications that prefer implementing
            // a different protection strategy can remove this handler from the handlers list and add
            // a custom one using a different approach (e.g by storing the value in the session state).

            if (string.IsNullOrEmpty(context.RequestForgeryProtection))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0344));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // Resolve the cookie builder from the OWIN integration options.
            var builder = _options.CurrentValue.CookieBuilder;

            // Unless a value was explicitly set in the options, use the expiration date
            // of the state token principal as the expiration date of the correlation cookie.
            var options = builder.Build(response.HttpContext);
            options.Expires ??= context.StateTokenPrincipal.GetExpirationDate();

            // Compute a collision-resistant and hard-to-guess cookie name based on the prefix set
            // in the options and the random request forgery protection claim generated earlier.
            var name = new StringBuilder(builder.Name)
                .Append(Separators.Dot)
                .Append(context.RequestForgeryProtection)
                .ToString();

            // Add the correlation cookie to the response headers.
            response.Cookies.Append(name, "v1", options);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for enabling the pass-through mode for the received request.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
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
                .AddFilter<RequireHttpRequest>()
                .AddFilter<TFilter>()
                .UseSingletonHandler<EnablePassthroughMode<TContext, TFilter>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.SkipRequest();

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching an appropriate HTTP status code.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public class AttachHttpResponseCode<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
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

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

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
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public class AttachCacheControlHeader<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
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

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // Prevent the response from being cached.
            response.Headers[HeaderNames.CacheControl] = "no-store";
            response.Headers[HeaderNames.Pragma] = "no-cache";
            response.Headers[HeaderNames.Expires] = "Thu, 01 Jan 1970 00:00:00 GMT";

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing OpenID Connect responses that must be handled by another
    /// middleware in the pipeline at a later stage (e.g an ASP.NET Core MVC action or a NancyFX module).
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
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
                .AddFilter<RequireHttpRequest>()
                .AddFilter<RequireErrorPassthroughEnabled>()
                .AddFilter<TFilter>()
                .UseSingletonHandler<ProcessPassthroughErrorResponse<TContext, TFilter>>()
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
    /// Contains the logic responsible for processing OpenID Connect responses handled by the status code pages middleware.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public class ProcessStatusCodePagesErrorResponse<TContext> : IOpenIddictClientHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .AddFilter<RequireStatusCodePagesIntegrationEnabled>()
                .UseSingletonHandler<ProcessStatusCodePagesErrorResponse<TContext>>()
                .SetOrder(ProcessPassthroughErrorResponse<TContext, IOpenIddictClientHandlerFilter<TContext>>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            if (string.IsNullOrEmpty(context.Transaction.Response.Error))
            {
                return default;
            }

            // Determine if the status code pages middleware has been enabled for this request.
            // If it was not registered or enabled, let the default OpenIddict client handlers render
            // a default error page instead of delegating the rendering to the status code middleware.
            var feature = response.HttpContext.Features.Get<IStatusCodePagesFeature>();
            if (feature is not { Enabled: true })
            {
                return default;
            }

            // Mark the request as fully handled to prevent the other OpenIddict client handlers
            // from displaying the default error page and to allow the status code pages middleware
            // to rewrite the response using the logic defined by the developer when registering it.
            context.HandleRequest();

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing context responses that must be returned as plain-text.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public class ProcessLocalErrorResponse<TContext> : IOpenIddictClientHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ProcessLocalErrorResponse<TContext>>()
                .SetOrder(ProcessStatusCodePagesErrorResponse<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

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
            await stream.CopyToAsync(response.Body, 4096, response.HttpContext.RequestAborted);

            context.HandleRequest();
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing OpenID Connect responses that don't specify any parameter.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public class ProcessEmptyResponse<TContext> : IOpenIddictClientHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ProcessEmptyResponse<TContext>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Logger.LogInformation(SR.GetResourceString(SR.ID6145));
            context.HandleRequest();

            return default;
        }
    }
}
