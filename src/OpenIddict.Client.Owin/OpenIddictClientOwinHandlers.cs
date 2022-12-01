/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Binary;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
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
        ResolveRequestUri.Descriptor,
        ValidateTransportSecurityRequirement.Descriptor,
        ValidateHostHeader.Descriptor,

        /*
         * Authentication processing:
         */
        ResolveRequestForgeryProtection.Descriptor,

        /*
         * Challenge processing:
         */
        ResolveHostChallengeProperties.Descriptor,
        ValidateTransportSecurityRequirementForChallenge.Descriptor,
        GenerateLoginCorrelationCookie.Descriptor,

        /*
         * Sign-out processing:
         */
        ResolveHostSignOutProperties.Descriptor,
        ValidateTransportSecurityRequirementForSignOut.Descriptor,
        GenerateLogoutCorrelationCookie.Descriptor)
        .AddRange(Authentication.DefaultHandlers)
        .AddRange(Session.DefaultHandlers);

    /// <summary>
    /// Contains the logic responsible for resolving the request URI from the OWIN environment.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ResolveRequestUri : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ResolveRequestUri>()
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

            // OpenIddict supports both absolute and relative URIs for all its endpoints, but only absolute
            // URIs can be properly canonicalized by the BCL System.Uri class (e.g './path/../' is normalized
            // to './' once the URI is fully constructed). At this stage of the request processing, rejecting
            // requests that lack the host information (e.g because HTTP/1.0 was used and no Host header was
            // sent by the HTTP client) is not desirable as it would affect all requests, including requests
            // that are not meant to be handled by OpenIddict itself. To avoid that, a fake host is temporarily
            // used to build an absolute base URI and a request URI that will be used to determine whether the
            // received request matches one of the addresses assigned to an OpenIddict endpoint. If the request
            // is later handled by OpenIddict, an additional check will be made to require the Host header.

            (context.BaseUri, context.RequestUri) = request.Host switch
            {
                { Value.Length: > 0 } host => (
                    BaseUri: new Uri(request.Scheme + Uri.SchemeDelimiter + host + request.PathBase, UriKind.Absolute),
                    RequestUri: request.Uri),

                { Value: null or { Length: 0 } } => (
                    BaseUri: new UriBuilder
                    {
                        Scheme = request.Scheme,
                        Path = request.PathBase.ToUriComponent()
                    }.Uri,
                    RequestUri: new UriBuilder
                    {
                        Scheme = request.Scheme,
                        Path = (request.PathBase + request.Path).ToUriComponent(),
                        Query = request.QueryString.ToUriComponent()
                    }.Uri)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting OpenID Connect requests that don't use transport security.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ValidateTransportSecurityRequirement : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireOwinRequest>()
                .AddFilter<RequireTransportSecurityRequirementEnabled>()
                .UseSingletonHandler<ValidateTransportSecurityRequirement>()
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

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Don't require that transport security be used if the request is not handled by OpenIddict.
            if (context.EndpointType is OpenIddictClientEndpointType.Unknown)
            {
                return default;
            }

            if (!request.IsSecure)
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2083),
                    uri: SR.FormatID8000(SR.ID2083));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the Host header extracted from the HTTP header.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ValidateHostHeader : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ValidateHostHeader>()
                .SetOrder(InferEndpointType.Descriptor.Order + 500)
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

            // Don't require that the request host be present if the request is not handled by OpenIddict.
            if (context.EndpointType is not OpenIddictClientEndpointType.Unknown &&
                string.IsNullOrEmpty(request.Host.Value))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2081(Headers.Host),
                    uri: SR.FormatID8000(SR.ID2081));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from GET or POST HTTP requests.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ExtractGetOrPostRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseValidatingContext
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
    /// Contains the logic responsible for resolving the request forgery protection from the correlation cookie.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ResolveRequestForgeryProtection : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientOwinOptions> _options;

        public ResolveRequestForgeryProtection(IOptionsMonitor<OpenIddictClientOwinOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireOwinRequest>()
                .AddFilter<RequireStateTokenValidated>()
                .UseSingletonHandler<ResolveRequestForgeryProtection>()
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

            // Resolve the nonce from the state token principal.
            var nonce = context.StateTokenPrincipal.GetClaim(Claims.Private.Nonce);
            if (string.IsNullOrEmpty(nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0354));
            }

            // Resolve the cookie manager and the cookie options from the OWIN integration options.
            var (manager, options) = (
                _options.CurrentValue.CookieManager,
                _options.CurrentValue.CookieOptions);

            // Compute the name of the cookie name based on the prefix and the random nonce.
            var name = new StringBuilder(_options.CurrentValue.CookieName)
                .Append(Separators.Dot)
                .Append(nonce)
                .ToString();

            // Try to find the correlation cookie matching the nonce stored in the state. If the cookie
            // cannot be found, this may indicate that the authorization response is unsolicited and
            // potentially malicious or be caused by an invalid or unadequate same-site configuration.
            //
            // In any case, the authentication demand MUST be rejected as it's impossible to ensure
            // it's not an injection or session fixation attack without the correlation cookie.
            var value = manager.GetRequestCookie(request.Context, name);
            if (string.IsNullOrEmpty(value))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2129),
                    uri: SR.FormatID8000(SR.ID2129));

                return default;
            }

            try
            {
                // Extract the payload and validate the version marker.
                var payload = Base64UrlEncoder.DecodeBytes(value);
                if (payload.Length < (1 + sizeof(uint)) || payload[0] is not 0x01)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2163),
                        uri: SR.FormatID8000(SR.ID2163));

                    return default;
                }

                // Extract the length of the request forgery protection.
                var length = (int) BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1, sizeof(uint)));
                if (length is 0 || length != (payload.Length - (1 + sizeof(uint))))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2163),
                        uri: SR.FormatID8000(SR.ID2163));

                    return default;
                }

                // Note: since the correlation cookie is not protected against tampering, an unexpected
                // value may be present in the cookie payload and this call may return a string whose
                // length doesn't match the expected value. In any case, any tampering attempt will be
                // detected when comparing the resolved value with the expected value stored in the state.
                context.RequestForgeryProtection = Encoding.UTF8.GetString(payload, index: 5, length);
            }

            catch
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2163),
                    uri: SR.FormatID8000(SR.ID2163));

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
    /// Contains the logic responsible for resolving the context-specific properties and parameters stored in the
    /// OWIN authentication properties specified by the application that triggered the challenge operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ResolveHostChallengeProperties : IOpenIddictClientHandler<ProcessChallengeContext>
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
                        Name: key[..^PropertyTypes.String.Length],
                        Value: new OpenIddictParameter(property.Value)),

                    // If the property ends with #boolean, return it as a boolean parameter.
                    string key when key.EndsWith(PropertyTypes.Boolean, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Boolean.Length],
                        Value: new OpenIddictParameter(bool.Parse(property.Value))),

                    // If the property ends with #integer, return it as an integer parameter.
                    string key when key.EndsWith(PropertyTypes.Integer, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Integer.Length],
                        Value: new OpenIddictParameter(long.Parse(property.Value, CultureInfo.InvariantCulture))),

                    // If the property ends with #json, return it as a JSON parameter.
                    string key when key.EndsWith(PropertyTypes.Json, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Json.Length],
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
    /// Contains the logic responsible for preventing challenge operations from being triggered from non-HTTPS endpoints.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ValidateTransportSecurityRequirementForChallenge : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireOwinRequest>()
                .AddFilter<RequireTransportSecurityRequirementEnabled>()
                .UseSingletonHandler<ValidateTransportSecurityRequirementForChallenge>()
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

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            if (!request.IsSecure)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0364));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for creating a correlation cookie that serves as a
    /// protection against state token injection, forged requests and session fixation attacks.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class GenerateLoginCorrelationCookie : IOpenIddictClientHandler<ProcessChallengeContext>
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

            if (string.IsNullOrEmpty(context.Nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0352));
            }

            if (string.IsNullOrEmpty(context.RequestForgeryProtection))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0343));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // This handler only applies to OWIN requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Compute a collision-resistant and hard-to-guess cookie name using the nonce.
            var name = new StringBuilder(_options.CurrentValue.CookieName)
                .Append(Separators.Dot)
                .Append(context.Nonce)
                .ToString();

            // Create the cookie payload containing...
            var count = Encoding.UTF8.GetByteCount(context.RequestForgeryProtection);
            var payload = new byte[1 + sizeof(uint) + count];

            // ... the version marker identifying the binary format used to create the payload (1 byte).
            payload[0] = 0x01;

            // ... the length of the request forgery protection (4 bytes).
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, sizeof(uint)), (uint) count);

            // ... the request forgery protection (variable length).
            var written = Encoding.UTF8.GetBytes(s: context.RequestForgeryProtection, charIndex: 0,
                charCount: context.RequestForgeryProtection.Length, bytes: payload, byteIndex: 5);
            Debug.Assert(written == count, SR.FormatID4016(written, count));

            // Resolve the cookie manager and the cookie options from the OWIN integration options.
            var (manager, options) = (
                _options.CurrentValue.CookieManager,
                _options.CurrentValue.CookieOptions);

            // Add the correlation cookie to the response headers.
            manager.AppendResponseCookie(response.Context, name, Base64UrlEncoder.Encode(payload), new CookieOptions
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
    public sealed class ResolveHostSignOutProperties : IOpenIddictClientHandler<ProcessSignOutContext>
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
                        Name: key[..^PropertyTypes.String.Length],
                        Value: new OpenIddictParameter(property.Value)),

                    // If the property ends with #boolean, return it as a boolean parameter.
                    string key when key.EndsWith(PropertyTypes.Boolean, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Boolean.Length],
                        Value: new OpenIddictParameter(bool.Parse(property.Value))),

                    // If the property ends with #integer, return it as an integer parameter.
                    string key when key.EndsWith(PropertyTypes.Integer, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Integer.Length],
                        Value: new OpenIddictParameter(long.Parse(property.Value, CultureInfo.InvariantCulture))),

                    // If the property ends with #json, return it as a JSON parameter.
                    string key when key.EndsWith(PropertyTypes.Json, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Json.Length],
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
    /// Contains the logic responsible for preventing sign-out operations from being triggered from non-HTTPS endpoints.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ValidateTransportSecurityRequirementForSignOut : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireOwinRequest>()
                .AddFilter<RequireTransportSecurityRequirementEnabled>()
                .UseSingletonHandler<ValidateTransportSecurityRequirementForSignOut>()
                .SetOrder(ValidateSignOutDemand.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            if (!request.IsSecure)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0365));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for creating a correlation cookie that serves as a
    /// protection against state token injection, forged requests and denial of service attacks.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class GenerateLogoutCorrelationCookie : IOpenIddictClientHandler<ProcessSignOutContext>
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

            if (string.IsNullOrEmpty(context.Nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0353));
            }

            if (string.IsNullOrEmpty(context.RequestForgeryProtection))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0344));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // This handler only applies to OWIN requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Compute a collision-resistant and hard-to-guess cookie name using the nonce.
            var name = new StringBuilder(_options.CurrentValue.CookieName)
                .Append(Separators.Dot)
                .Append(context.Nonce)
                .ToString();

            // Create the cookie payload containing...
            var count = Encoding.UTF8.GetByteCount(context.RequestForgeryProtection);
            var payload = new byte[1 + sizeof(uint) + count];

            // ... the version marker identifying the binary format used to create the payload (1 byte).
            payload[0] = 0x01;

            // ... the length of the request forgery protection (4 bytes).
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, sizeof(uint)), (uint) count);

            // ... the request forgery protection (variable length).
            var written = Encoding.UTF8.GetBytes(s: context.RequestForgeryProtection, charIndex: 0,
                charCount: context.RequestForgeryProtection.Length, bytes: payload, byteIndex: 5);
            Debug.Assert(written == count, SR.FormatID4016(written, count));

            // Resolve the cookie manager and the cookie options from the OWIN integration options.
            var (manager, options) = (
                _options.CurrentValue.CookieManager,
                _options.CurrentValue.CookieOptions);

            // Add the correlation cookie to the response headers.
            manager.AppendResponseCookie(response.Context, name, Base64UrlEncoder.Encode(payload), new CookieOptions
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
    public sealed class EnablePassthroughMode<TContext, TFilter> : IOpenIddictClientHandler<TContext>
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
    public sealed class AttachHttpResponseCode<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
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
    public sealed class AttachOwinResponseChallenge<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
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
    public sealed class SuppressFormsAuthenticationRedirect<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
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
    public sealed class AttachCacheControlHeader<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
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
    public sealed class ProcessPassthroughErrorResponse<TContext, TFilter> : IOpenIddictClientHandler<TContext>
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
    public sealed class ProcessLocalErrorResponse<TContext> : IOpenIddictClientHandler<TContext>
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
    public sealed class ProcessEmptyResponse<TContext> : IOpenIddictClientHandler<TContext>
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
