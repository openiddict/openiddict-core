/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Binary;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
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
        ResolveRequestUri.Descriptor,
        ValidateTransportSecurityRequirement.Descriptor,
        ValidateHostHeader.Descriptor,

        /*
         * Authentication processing:
         */
        ValidateAuthenticationNonce.Descriptor,
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
    /// Contains the logic responsible for resolving the request URI from the ASP.NET Core environment.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ResolveRequestUri : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireHttpRequest>()
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

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // OpenIddict supports both absolute and relative URIs for all its endpoints, but only absolute
            // URIs can be properly canonicalized by the BCL System.Uri class (e.g './path/../' is normalized
            // to './' once the URI is fully constructed). At this stage of the request processing, rejecting
            // requests that lack the host information (e.g because HTTP/1.0 was used and no Host header was
            // sent by the HTTP client) is not desirable as it would affect all requests, including requests
            // that are not meant to be handled by OpenIddict itself. To avoid that, a fake host is temporarily
            // used to build an absolute base URI and a request URI that will be used to determine whether the
            // received request matches one of the URIs assigned to an OpenIddict endpoint. If the request
            // is later handled by OpenIddict, an additional check will be made to require the Host header.

            (context.BaseUri, context.RequestUri) = request.Host switch
            {
                { HasValue: true } host => (
                    BaseUri: new Uri(request.Scheme + Uri.SchemeDelimiter + host + request.PathBase, UriKind.Absolute),
                    RequestUri: new Uri(request.GetEncodedUrl(), UriKind.Absolute)),

                { HasValue: false } => (
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
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ValidateTransportSecurityRequirement : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireHttpRequest>()
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

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // Don't require that transport security be used if the request is not handled by OpenIddict.
            if (context.EndpointType is not OpenIddictClientEndpointType.Unknown && !request.IsHttps)
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
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ValidateHostHeader : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ValidateHostHeader>()
                .SetOrder(ValidateTransportSecurityRequirement.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
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

            // Don't require that the request host be present if the request is not handled by OpenIddict.
            if (context.EndpointType is not OpenIddictClientEndpointType.Unknown && !request.Host.HasValue)
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2081(HeaderNames.Host),
                    uri: SR.FormatID8000(SR.ID2081));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from GET or POST HTTP requests.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ExtractGetOrPostRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseValidatingContext
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
    /// Contains the logic responsible for rejecting authentication demands that specify an explicit nonce property.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ValidateAuthenticationNonce : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ValidateAuthenticationNonce>()
                .SetOrder(ValidateAuthenticationDemand.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (!string.IsNullOrEmpty(context.Nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0377));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the request forgery protection from the correlation cookie.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ResolveRequestForgeryProtection : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientAspNetCoreOptions> _options;

        public ResolveRequestForgeryProtection(IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireHttpRequest>()
                .AddFilter<RequireStateTokenPrincipal>()
                .AddFilter<RequireStateTokenValidated>()
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

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // Resolve the nonce from the state token principal.
            var nonce = context.StateTokenPrincipal.GetClaim(Claims.Private.Nonce);
            if (string.IsNullOrEmpty(nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0354));
            }

            // Resolve the cookie builder from the OWIN integration options.
            var builder = _options.CurrentValue.CookieBuilder;

            // Compute the name of the cookie name based on the prefix and the random nonce.
            var name = new StringBuilder(builder.Name)
                .Append(Separators.Dot)
                .Append(nonce)
                .ToString();

            // Try to find the correlation cookie matching the nonce stored in the state. If the cookie
            // cannot be found, this may indicate that the authorization response is unsolicited and
            // potentially malicious or be caused by an invalid or unadequate same-site configuration.
            //
            // In any case, the authentication demand MUST be rejected as it's impossible to ensure
            // it's not an injection or session fixation attack without the correlation cookie.
            var value = request.Cookies[name];
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
            request.HttpContext.Response.Cookies.Delete(name, builder.Build(request.HttpContext));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the context-specific properties and parameters stored in the
    /// ASP.NET Core authentication properties specified by the application that triggered the challenge operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ResolveHostChallengeProperties : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireHttpRequest>()
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
            if (properties is { Items.Count: > 0 })
            {
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

                // If a target link URI was specified, attach it to the context.
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

                foreach (var property in properties.Items)
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            if (properties is { Parameters.Count: > 0 })
            {
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
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preventing challenge operations from being triggered from non-HTTPS endpoints.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ValidateTransportSecurityRequirementForChallenge : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireHttpRequest>()
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

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            if (!request.IsHttps)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0364));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for creating a correlation cookie that serves as a
    /// protection against state token injection, forged requests and session fixation attacks.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class GenerateLoginCorrelationCookie : IOpenIddictClientHandler<ProcessChallengeContext>
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

            if (string.IsNullOrEmpty(context.Nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0352));
            }

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

            // Compute a collision-resistant and hard-to-guess cookie name using the nonce.
            var name = new StringBuilder(builder.Name)
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

            // Add the correlation cookie to the response headers.
            response.Cookies.Append(name, Base64UrlEncoder.Encode(payload), options);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the context-specific properties and parameters stored in the
    /// ASP.NET Core authentication properties specified by the application that triggered the sign-out operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ResolveHostSignOutProperties : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireHttpRequest>()
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
            if (properties is { Items.Count: > 0 })
            {
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

                // If a target link URI was specified, attach it to the context.
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

                foreach (var property in properties.Items)
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            if (properties is { Parameters.Count: > 0 })
            {
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
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preventing sign-out operations from being triggered from non-HTTPS endpoints.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ValidateTransportSecurityRequirementForSignOut : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireHttpRequest>()
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

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            if (!request.IsHttps)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0365));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for creating a correlation cookie that serves as a
    /// protection against state token injection, forged requests and denial of service attacks.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class GenerateLogoutCorrelationCookie : IOpenIddictClientHandler<ProcessSignOutContext>
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

            if (string.IsNullOrEmpty(context.Nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0353));
            }

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

            // Compute a collision-resistant and hard-to-guess cookie name using the nonce.
            var name = new StringBuilder(builder.Name)
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

            // Add the correlation cookie to the response headers.
            response.Cookies.Append(name, Base64UrlEncoder.Encode(payload), options);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for enabling the pass-through mode for the received request.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
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
    public sealed class AttachHttpResponseCode<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
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
    public sealed class AttachCacheControlHeader<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
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
    public sealed class ProcessPassthroughErrorResponse<TContext, TFilter> : IOpenIddictClientHandler<TContext>
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
    public sealed class ProcessStatusCodePagesErrorResponse<TContext> : IOpenIddictClientHandler<TContext>
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
    public sealed class ProcessLocalErrorResponse<TContext> : IOpenIddictClientHandler<TContext>
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
    public sealed class ProcessEmptyResponse<TContext> : IOpenIddictClientHandler<TContext>
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
