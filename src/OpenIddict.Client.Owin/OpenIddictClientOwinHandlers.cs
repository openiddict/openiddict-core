/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Extensions;
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
        ValidateEndpointUri.Descriptor,

        /*
         * Challenge processing:
         */
        ResolveHostChallengeProperties.Descriptor,
        GenerateLoginCorrelationCookie.Descriptor,

        /*
         * Sign-out processing:
         */
        ResolveHostSignOutProperties.Descriptor,
        GenerateLogoutCorrelationCookie.Descriptor)
        .AddRange(Authentication.DefaultHandlers)
        .AddRange(Session.DefaultHandlers);

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
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            context.EndpointType =
                Matches(request, context.Options.PostLogoutRedirectionEndpointUris) ? OpenIddictClientEndpointType.PostLogoutRedirection :
                Matches(request, context.Options.RedirectionEndpointUris)           ? OpenIddictClientEndpointType.Redirection :
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
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

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
    /// Contains the logic responsible for validating the correlation cookie that serves as a
    /// protection against state token injection, forged requests and session fixation attacks.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class ValidateCorrelationCookie : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientOwinOptions> _options;

        public ValidateCorrelationCookie(IOptionsMonitor<OpenIddictClientOwinOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

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
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // This handler only applies to OWIN requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Resolve the request forgery protection from the state token principal.
            var identifier = context.StateTokenPrincipal.GetClaim(Claims.RequestForgeryProtection);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0339));
            }

            // Resolve the cookie manager and the cookie options from the OWIN integration options.
            var (manager, options) = (
                _options.CurrentValue.CookieManager,
                _options.CurrentValue.CookieOptions);

            // Compute the name of the cookie name based on the prefix set in the options
            // and the random request forgery protection claim restored from the state.
            var name = new StringBuilder(_options.CurrentValue.CookieName)
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
    /// Contains the logic responsible for comparing the current request URL to the expected URL stored in the state token.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class ValidateEndpointUri : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireOwinRequest>()
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

            // This handler only applies to OWIN requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Resolve the endpoint type allowed to be used with the state token.
            if (!Enum.TryParse(context.StateTokenPrincipal.GetClaim(Claims.Private.EndpointType),
                ignoreCase: true, out OpenIddictClientEndpointType type))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0340));
            }

            // Resolve the endpoint address from either the redirect_uri or post_logout_redirect_uri
            // depending on the type of endpoint allowed to receive the specified state token.
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
            if (!string.IsNullOrEmpty(address.Query) && OpenIddictHelpers.ParseQuery(address.Query)
                // Note: ignore parameters that only include empty values
                // to match the logic used by OWIN for IOwinRequest.Query.
                .Where(parameter => parameter.Value.Any(value => !string.IsNullOrEmpty(value)))
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
    /// Contains the logic responsible for resolving the context-specific properties and parameters stored in the
    /// OWIN authentication properties specified by the application that triggered the challenge operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class ResolveHostChallengeProperties : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ResolveHostChallengeProperties>()
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

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is not { Dictionary.Count: > 0 })
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

            // If a provider name was explicitly set, update the challenge context to use it.
            if (properties.Dictionary.TryGetValue(Properties.ProviderName, out string? provider) &&
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
            if (properties.Dictionary.TryGetValue(Properties.IdentityTokenHint, out string? token) &&
                !string.IsNullOrEmpty(token))
            {
                context.IdentityTokenHint = token;
            }

            // If a login hint was specified, attach it to the context.
            if (properties.Dictionary.TryGetValue(Properties.LoginHint, out string? hint) &&
                !string.IsNullOrEmpty(hint))
            {
                context.LoginHint = hint;
            }

            // Note: unlike ASP.NET Core, OWIN's AuthenticationProperties doesn't offer a strongly-typed
            // dictionary that allows flowing parameters while preserving their original types. To allow
            // returning custom parameters, the OWIN host allows using AuthenticationProperties.Dictionary
            // but requires suffixing the properties that are meant to be used as parameters using a special
            // suffix that indicates that the property is public and determines its actual representation.
            foreach (var property in properties.Dictionary)
            {
                var (name, value) = property.Key switch
                {
                    // If the property ends with #string, represent it as a string parameter.
                    string key when key.EndsWith(PropertyTypes.String, StringComparison.OrdinalIgnoreCase) => (
                        Name: key.Substring(0, key.Length - PropertyTypes.String.Length),
                        Value: new OpenIddictParameter(property.Value)),

                    // If the property ends with #boolean, return it as a boolean parameter.
                    string key when key.EndsWith(PropertyTypes.Boolean, StringComparison.OrdinalIgnoreCase) => (
                        Name: key.Substring(0, key.Length - PropertyTypes.Boolean.Length),
                        Value: new OpenIddictParameter(bool.Parse(property.Value))),

                    // If the property ends with #integer, return it as an integer parameter.
                    string key when key.EndsWith(PropertyTypes.Integer, StringComparison.OrdinalIgnoreCase) => (
                        Name: key.Substring(0, key.Length - PropertyTypes.Integer.Length),
                        Value: new OpenIddictParameter(long.Parse(property.Value, CultureInfo.InvariantCulture))),

                    // If the property ends with #json, return it as a JSON parameter.
                    string key when key.EndsWith(PropertyTypes.Json, StringComparison.OrdinalIgnoreCase) => (
                        Name: key.Substring(0, key.Length - PropertyTypes.Json.Length),
                        Value: new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(property.Value))),

                    _ => default
                };

                if (!string.IsNullOrEmpty(name))
                {
                    context.Parameters[name] = value;
                }

                else
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for creating a correlation cookie that serves as a
    /// protection against state token injection, forged requests and session fixation attacks.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class GenerateLoginCorrelationCookie : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientOwinOptions> _options;

        public GenerateLoginCorrelationCookie(IOptionsMonitor<OpenIddictClientOwinOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireOwinRequest>()
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
    /// Contains the logic responsible for resolving the context-specific properties and parameters stored in the
    /// OWIN authentication properties specified by the application that triggered the sign-out operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class ResolveHostSignOutProperties : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ResolveHostSignOutProperties>()
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

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is not { Dictionary.Count: > 0 })
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

            // If a provider name was explicitly set, update the sign-out context to use it.
            if (properties.Dictionary.TryGetValue(Properties.ProviderName, out string? provider) &&
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
            if (properties.Dictionary.TryGetValue(Properties.IdentityTokenHint, out string? token) &&
                !string.IsNullOrEmpty(token))
            {
                context.IdentityTokenHint = token;
            }

            // If a login hint was specified, attach it to the context.
            if (properties.Dictionary.TryGetValue(Properties.LoginHint, out string? hint) &&
                !string.IsNullOrEmpty(hint))
            {
                context.LoginHint = hint;
            }

            // Note: unlike ASP.NET Core, OWIN's AuthenticationProperties doesn't offer a strongly-typed
            // dictionary that allows flowing parameters while preserving their original types. To allow
            // returning custom parameters, the OWIN host allows using AuthenticationProperties.Dictionary
            // but requires suffixing the properties that are meant to be used as parameters using a special
            // suffix that indicates that the property is public and determines its actual representation.
            foreach (var property in properties.Dictionary)
            {
                var (name, value) = property.Key switch
                {
                    // If the property ends with #string, represent it as a string parameter.
                    string key when key.EndsWith(PropertyTypes.String, StringComparison.OrdinalIgnoreCase) => (
                        Name: key.Substring(0, key.Length - PropertyTypes.String.Length),
                        Value: new OpenIddictParameter(property.Value)),

                    // If the property ends with #boolean, return it as a boolean parameter.
                    string key when key.EndsWith(PropertyTypes.Boolean, StringComparison.OrdinalIgnoreCase) => (
                        Name: key.Substring(0, key.Length - PropertyTypes.Boolean.Length),
                        Value: new OpenIddictParameter(bool.Parse(property.Value))),

                    // If the property ends with #integer, return it as an integer parameter.
                    string key when key.EndsWith(PropertyTypes.Integer, StringComparison.OrdinalIgnoreCase) => (
                        Name: key.Substring(0, key.Length - PropertyTypes.Integer.Length),
                        Value: new OpenIddictParameter(long.Parse(property.Value, CultureInfo.InvariantCulture))),

                    // If the property ends with #json, return it as a JSON parameter.
                    string key when key.EndsWith(PropertyTypes.Json, StringComparison.OrdinalIgnoreCase) => (
                        Name: key.Substring(0, key.Length - PropertyTypes.Json.Length),
                        Value: new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(property.Value))),

                    _ => default
                };

                if (!string.IsNullOrEmpty(name))
                {
                    context.Parameters[name] = value;
                }

                else
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for creating a correlation cookie that serves as a
    /// protection against state token injection, forged requests and denial of service attacks.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class GenerateLogoutCorrelationCookie : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientOwinOptions> _options;

        public GenerateLogoutCorrelationCookie(IOptionsMonitor<OpenIddictClientOwinOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireOwinRequest>()
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
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

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
    /// Contains the logic responsible for attaching an OWIN response chalenge to the context, if necessary.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class AttachOwinResponseChallenge<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<AttachOwinResponseChallenge<TContext>>()
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

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // OWIN authentication middleware configured to use active authentication (which is the default mode)
            // are known to aggressively intercept 401 responses even if the request is already considered fully
            // handled. In practice, this behavior is often seen with the cookies authentication middleware,
            // that will rewrite the 401 responses returned by OpenIddict and try to redirect the user agent
            // to the login page configured in the options. To prevent this undesirable behavior, a fake
            // response challenge pointing to a non-existent middleware is manually added to the OWIN context
            // to prevent the active authentication middleware from rewriting OpenIddict's 401 HTTP responses.
            //
            // Note: while 403 responses are generally not intercepted by the built-in OWIN authentication
            // middleware, they are treated the same way as 401 responses to account for custom middleware
            // that may potentially use the same interception logic for both 401 and 403 HTTP responses.
            if (response.StatusCode is 401 or 403 &&
                response.Context.Authentication.AuthenticationResponseChallenge is null)
            {
                response.Context.Authentication.AuthenticationResponseChallenge =
                    new AuthenticationResponseChallenge(new[] { Guid.NewGuid().ToString() }, null);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for suppressing the redirection applied by FormsAuthenticationModule, if necessary.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class SuppressFormsAuthenticationRedirect<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<SuppressFormsAuthenticationRedirect<TContext>>()
                .SetOrder(AttachOwinResponseChallenge<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Similarly to the automatic authentication mode used by OWIN authentication middleware,
            // the ASP.NET FormsAuthentication module aggressively intercepts 401 responses even if
            // the request has already been fully handled by another component (like OpenIddict).
            // To prevent that, this handler is responsible for suppressing the redirection enforced
            // by FormsAuthenticationModule when the status code was set to 401 (the only status code
            // used by the FormsAuthenticationModule) and the OWIN application is hosted on SystemWeb.
            if (response.StatusCode is 401)
            {
                TrySuppressFormsAuthenticationRedirect(response.Environment);
            }

            return default;

            static void TrySuppressFormsAuthenticationRedirect(IDictionary<string, object> environment)
            {
                // Note: the OWIN host cannot depend on the OWIN SystemWeb package but a direct access
                // to the underlying ASP.NET 4.x context is required to be able to disable the redirection
                // enforced by the FormsAuthentication module. To work around that, the HttpContextBase
                // instance is resolved from the OWIN environment and SuppressFormsAuthenticationRedirect
                // is set to true using a dynamic runtime resolution (that uses reflection under the hood).
                if (environment.TryGetValue("System.Web.HttpContextBase", out dynamic context))
                {
                    try
                    {
                        // Note: the SuppressFormsAuthenticationRedirect property was introduced in ASP.NET 4.5
                        // and thus should always be present, as OpenIddict requires targeting ASP.NET >= 4.6.1.
                        context.Response.SuppressFormsAuthenticationRedirect = true;
                    }

                    catch
                    {
                    }
                }
            }
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
                .SetOrder(SuppressFormsAuthenticationRedirect<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

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
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

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
