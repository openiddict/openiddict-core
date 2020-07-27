/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreHandlerFilters;
using static OpenIddict.Server.OpenIddictServerEvents;
using JsonWebTokenTypes = OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants.JsonWebTokenTypes;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.AspNetCore
{
    public static partial class OpenIddictServerAspNetCoreHandlers
    {
        public static class Session
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Logout request extraction:
                 */
                ExtractGetOrPostRequest<ExtractLogoutRequestContext>.Descriptor,
                RestoreCachedRequestParameters.Descriptor,
                CacheRequestParameters.Descriptor,

                /*
                 * Logout request handling:
                 */
                EnablePassthroughMode<HandleLogoutRequestContext, RequireLogoutEndpointPassthroughEnabled>.Descriptor,

                /*
                 * Logout response processing:
                 */
                RemoveCachedRequest.Descriptor,
                AttachHttpResponseCode<ApplyLogoutResponseContext>.Descriptor,
                AttachCacheControlHeader<ApplyLogoutResponseContext>.Descriptor,
                ProcessRedirectionResponse.Descriptor,
                ProcessPassthroughErrorResponse<ApplyLogoutResponseContext, RequireLogoutEndpointPassthroughEnabled>.Descriptor,
                ProcessStatusCodePagesErrorResponse<ApplyLogoutResponseContext>.Descriptor,
                ProcessLocalErrorResponse<ApplyLogoutResponseContext>.Descriptor,
                ProcessHostRedirectionResponse<ApplyLogoutResponseContext>.Descriptor,
                ProcessEmptyResponse<ApplyLogoutResponseContext>.Descriptor);

            /// <summary>
            /// Contains the logic responsible of restoring cached requests from the request_id, if specified.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
            /// </summary>
            public class RestoreCachedRequestParameters : IOpenIddictServerHandler<ExtractLogoutRequestContext>
            {
                private readonly IDistributedCache _cache;

                public RestoreCachedRequestParameters() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1115));

                public RestoreCachedRequestParameters(IDistributedCache cache)
                    => _cache = cache;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractLogoutRequestContext>()
                        .AddFilter<RequireHttpRequest>()
                        .AddFilter<RequireLogoutEndpointCachingEnabled>()
                        .UseSingletonHandler<RestoreCachedRequestParameters>()
                        .SetOrder(ExtractGetOrPostRequest<ExtractLogoutRequestContext>.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ExtractLogoutRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(context.Request != null, SR.GetResourceString(SR.ID5008));

                    // If a request_id parameter can be found in the logout request,
                    // restore the complete logout request from the distributed cache.

                    if (string.IsNullOrEmpty(context.Request.RequestId))
                    {
                        return;
                    }

                    // Note: the cache key is always prefixed with a specific marker
                    // to avoid collisions with the other types of cached payloads.
                    var token = await _cache.GetStringAsync(Cache.LogoutRequest + context.Request.RequestId);
                    if (token == null || !context.Options.JsonWebTokenHandler.CanReadToken(token))
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID7150), Parameters.RequestId);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: context.Localizer[SR.ID3052, Parameters.RequestId]);

                        return;
                    }

                    var parameters = context.Options.TokenValidationParameters.Clone();
                    parameters.ValidIssuer ??= context.Issuer?.AbsoluteUri;
                    parameters.ValidAudience = context.Issuer?.AbsoluteUri;
                    parameters.ValidTypes = new[] { JsonWebTokenTypes.Private.LogoutRequest };

                    var result = context.Options.JsonWebTokenHandler.ValidateToken(token, parameters);
                    if (!result.IsValid)
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID7150), Parameters.RequestId);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: context.Localizer[SR.ID3052, Parameters.RequestId]);

                        return;
                    }

                    using var document = JsonDocument.Parse(
                        Base64UrlEncoder.Decode(((JsonWebToken) result.SecurityToken).InnerToken.EncodedPayload));
                    if (document.RootElement.ValueKind != JsonValueKind.Object)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1117));
                    }

                    // Restore the authorization request parameters from the serialized payload.
                    foreach (var parameter in document.RootElement.EnumerateObject())
                    {
                        // Avoid overriding the current request parameters.
                        if (context.Request.HasParameter(parameter.Name))
                        {
                            continue;
                        }

                        context.Request.SetParameter(parameter.Name, parameter.Value.Clone());
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of caching logout requests, if applicable.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
            /// </summary>
            public class CacheRequestParameters : IOpenIddictServerHandler<ExtractLogoutRequestContext>
            {
                private readonly IDistributedCache _cache;
                private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

                public CacheRequestParameters() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1115));

                public CacheRequestParameters(
                    IDistributedCache cache,
                    IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
                {
                    _cache = cache;
                    _options = options;
                }

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractLogoutRequestContext>()
                        .AddFilter<RequireHttpRequest>()
                        .AddFilter<RequireLogoutEndpointCachingEnabled>()
                        .UseSingletonHandler<CacheRequestParameters>()
                        .SetOrder(RestoreCachedRequestParameters.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ExtractLogoutRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(context.Request != null, SR.GetResourceString(SR.ID5008));

                    // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                    // this may indicate that the request was incorrectly processed by another server stack.
                    var request = context.Transaction.GetHttpRequest();
                    if (request == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1113));
                    }

                    // Don't cache the request if the request doesn't include any parameter.
                    // If a request_id parameter can be found in the logout request,
                    // ignore the following logic to prevent an infinite redirect loop.
                    if (context.Request.Count == 0 || !string.IsNullOrEmpty(context.Request.RequestId))
                    {
                        return;
                    }

                    // Generate a 256-bit request identifier using a crypto-secure random number generator.
                    var data = new byte[256 / 8];

#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                    RandomNumberGenerator.Fill(data);
#else
                    using var generator = RandomNumberGenerator.Create();
                    generator.GetBytes(data);
#endif

                    context.Request.RequestId = Base64UrlEncoder.Encode(data);

                    // Store the serialized logout request parameters in the distributed cache.
                    var token = context.Options.JsonWebTokenHandler.CreateToken(new SecurityTokenDescriptor
                    {
                        AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.LogoutRequest
                        },
                        Audience = context.Issuer?.AbsoluteUri,
                        Claims = context.Request.GetParameters().ToDictionary(
                            parameter => parameter.Key,
                            parameter => parameter.Value.Value),
                        Issuer = context.Issuer?.AbsoluteUri,
                        SigningCredentials = context.Options.SigningCredentials.First(),
                        Subject = new ClaimsIdentity()
                    });

                    token = context.Options.JsonWebTokenHandler.EncryptToken(token,
                        encryptingCredentials: context.Options.EncryptionCredentials.First(),
                        additionalHeaderClaims: new Dictionary<string, object>
                        {
                            [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.AuthorizationRequest
                        });

                    // Note: the cache key is always prefixed with a specific marker
                    // to avoid collisions with the other types of cached payloads.
                    await _cache.SetStringAsync(Cache.LogoutRequest + context.Request.RequestId,
                        token, _options.CurrentValue.AuthorizationEndpointCachingPolicy);

                    // Create a new GET logout request containing only the request_id parameter.
                    var address = QueryHelpers.AddQueryString(
                        uri: request.Scheme + "://" + request.Host + request.PathBase + request.Path,
                        name: Parameters.RequestId,
                        value: context.Request.RequestId);

                    request.HttpContext.Response.Redirect(address);

                    // Mark the response as handled to skip the rest of the pipeline.
                    context.HandleRequest();
                }
            }

            /// <summary>
            /// Contains the logic responsible of removing cached logout requests from the distributed cache.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
            /// </summary>
            public class RemoveCachedRequest : IOpenIddictServerHandler<ApplyLogoutResponseContext>
            {
                private readonly IDistributedCache _cache;

                public RemoveCachedRequest() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1115));

                public RemoveCachedRequest(IDistributedCache cache)
                    => _cache = cache;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyLogoutResponseContext>()
                        .AddFilter<RequireHttpRequest>()
                        .AddFilter<RequireLogoutEndpointCachingEnabled>()
                        .UseSingletonHandler<RemoveCachedRequest>()
                        .SetOrder(ProcessRedirectionResponse.Descriptor.Order - 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(ApplyLogoutResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (string.IsNullOrEmpty(context.Request?.RequestId))
                    {
                        return default;
                    }

                    // Note: the ApplyLogoutResponse event is called for both successful
                    // and errored logout responses but discrimination is not necessary here,
                    // as the logout request must be removed from the distributed cache in both cases.

                    // Note: the cache key is always prefixed with a specific marker
                    // to avoid collisions with the other types of cached payloads.
                    return new ValueTask(_cache.RemoveAsync(Cache.LogoutRequest + context.Request.RequestId));
                }
            }

            /// <summary>
            /// Contains the logic responsible of processing logout responses.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
            /// </summary>
            public class ProcessRedirectionResponse : IOpenIddictServerHandler<ApplyLogoutResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyLogoutResponseContext>()
                        .AddFilter<RequireHttpRequest>()
                        .UseSingletonHandler<ProcessRedirectionResponse>()
                        .SetOrder(ProcessStatusCodePagesErrorResponse<ApplyLogoutResponseContext>.Descriptor.Order - 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(ApplyLogoutResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                    // this may indicate that the request was incorrectly processed by another server stack.
                    var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                    if (response == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1113));
                    }

                    if (string.IsNullOrEmpty(context.PostLogoutRedirectUri))
                    {
                        return default;
                    }

                    context.Logger.LogInformation(SR.GetResourceString(SR.ID7151), context.PostLogoutRedirectUri, response);

                    var location = context.PostLogoutRedirectUri;

                    // Note: while initially not allowed by the core OAuth 2.0 specification, multiple parameters
                    // with the same name are used by derived drafts like the OAuth 2.0 token exchange specification.
                    // For consistency, multiple parameters with the same name are also supported by this endpoint.
                    foreach (var (key, value) in
                        from parameter in context.Response.GetParameters()
                        let values = (string?[]?) parameter.Value
                        where values != null
                        from value in values
                        where !string.IsNullOrEmpty(value)
                        select (parameter.Key, Value: value))
                    {
                        location = QueryHelpers.AddQueryString(location, key, value);
                    }

                    response.Redirect(location);
                    context.HandleRequest();

                    return default;
                }
            }
        }
    }
}
