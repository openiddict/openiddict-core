/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
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
        public static class Authentication
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Authorization request extraction:
                 */
                ExtractGetOrPostRequest<ExtractAuthorizationRequestContext>.Descriptor,
                RestoreCachedRequestParameters.Descriptor,
                CacheRequestParameters.Descriptor,

                /*
                 * Authorization request handling:
                 */
                EnablePassthroughMode<HandleAuthorizationRequestContext, RequireAuthorizationEndpointPassthroughEnabled>.Descriptor,

                /*
                 * Authorization response processing:
                 */
                RemoveCachedRequest.Descriptor,
                AttachHttpResponseCode<ApplyAuthorizationResponseContext>.Descriptor,
                AttachCacheControlHeader<ApplyAuthorizationResponseContext>.Descriptor,
                ProcessFormPostResponse.Descriptor,
                ProcessQueryResponse.Descriptor,
                ProcessFragmentResponse.Descriptor,
                ProcessPassthroughErrorResponse<ApplyAuthorizationResponseContext, RequireAuthorizationEndpointPassthroughEnabled>.Descriptor,
                ProcessStatusCodePagesErrorResponse<ApplyAuthorizationResponseContext>.Descriptor,
                ProcessLocalErrorResponse<ApplyAuthorizationResponseContext>.Descriptor);

            /// <summary>
            /// Contains the logic responsible of restoring cached requests from the request_id, if specified.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
            /// </summary>
            public class RestoreCachedRequestParameters : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
            {
                private readonly IDistributedCache _cache;

                public RestoreCachedRequestParameters() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0116));

                public RestoreCachedRequestParameters(IDistributedCache cache)
                    => _cache = cache;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
                        .AddFilter<RequireHttpRequest>()
                        .AddFilter<RequireAuthorizationRequestCachingEnabled>()
                        .UseSingletonHandler<RestoreCachedRequestParameters>()
                        .SetOrder(ExtractGetOrPostRequest<ExtractAuthorizationRequestContext>.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(context.Request is not null, SR.GetResourceString(SR.ID4008));

                    // If a request_id parameter can be found in the authorization request,
                    // restore the complete authorization request from the distributed cache.

                    if (string.IsNullOrEmpty(context.Request.RequestId))
                    {
                        return;
                    }

                    // Note: the cache key is always prefixed with a specific marker
                    // to avoid collisions with the other types of cached payloads.
                    var token = await _cache.GetStringAsync(Cache.AuthorizationRequest + context.Request.RequestId);
                    if (token is null || !context.Options.JsonWebTokenHandler.CanReadToken(token))
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID6146), Parameters.RequestId);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2052(Parameters.RequestId),
                            uri: SR.FormatID8000(SR.ID2052));

                        return;
                    }

                    var parameters = context.Options.TokenValidationParameters.Clone();
                    parameters.ValidIssuer ??= context.Issuer?.AbsoluteUri;
                    parameters.ValidAudience = context.Issuer?.AbsoluteUri;
                    parameters.ValidTypes = new[] { JsonWebTokenTypes.Private.AuthorizationRequest };

                    var result = context.Options.JsonWebTokenHandler.ValidateToken(token, parameters);
                    if (!result.IsValid)
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID6146), Parameters.RequestId);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2052(Parameters.RequestId),
                            uri: SR.FormatID8000(SR.ID2052));

                        return;
                    }

                    using var document = JsonDocument.Parse(
                        Base64UrlEncoder.Decode(((JsonWebToken) result.SecurityToken).InnerToken.EncodedPayload));
                    if (document.RootElement.ValueKind != JsonValueKind.Object)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0117));
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
            /// Contains the logic responsible of caching authorization requests, if applicable.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
            /// </summary>
            public class CacheRequestParameters : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
            {
                private readonly IDistributedCache _cache;
                private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

                public CacheRequestParameters() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0116));

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
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
                        .AddFilter<RequireHttpRequest>()
                        .AddFilter<RequireAuthorizationRequestCachingEnabled>()
                        .UseSingletonHandler<CacheRequestParameters>()
                        .SetOrder(RestoreCachedRequestParameters.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(context.Request is not null, SR.GetResourceString(SR.ID4008));

                    // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                    // this may indicate that the request was incorrectly processed by another server stack.
                    var request = context.Transaction.GetHttpRequest();
                    if (request is null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                    }

                    // Don't cache the request if the request doesn't include any parameter.
                    // If a request_id parameter can be found in the authorization request,
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

                    // Store the serialized authorization request parameters in the distributed cache.
                    var token = context.Options.JsonWebTokenHandler.CreateToken(new SecurityTokenDescriptor
                    {
                        Audience = context.Issuer?.AbsoluteUri,
                        Claims = context.Request.GetParameters().ToDictionary(
                            parameter => parameter.Key,
                            parameter => parameter.Value.Value),
                        EncryptingCredentials = context.Options.EncryptionCredentials.First(),
                        Issuer = context.Issuer?.AbsoluteUri,
                        SigningCredentials = context.Options.SigningCredentials.First(),
                        Subject = new ClaimsIdentity(),
                        TokenType = JsonWebTokenTypes.Private.AuthorizationRequest
                    });

                    // Note: the cache key is always prefixed with a specific marker
                    // to avoid collisions with the other types of cached payloads.
                    await _cache.SetStringAsync(Cache.AuthorizationRequest + context.Request.RequestId,
                        token, _options.CurrentValue.AuthorizationRequestCachingPolicy);

                    // Create a new GET authorization request containing only the request_id parameter.
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
            /// Contains the logic responsible of removing cached authorization requests from the distributed cache.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
            /// </summary>
            public class RemoveCachedRequest : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
            {
                private readonly IDistributedCache _cache;

                public RemoveCachedRequest() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0116));

                public RemoveCachedRequest(IDistributedCache cache)
                    => _cache = cache;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                        .AddFilter<RequireHttpRequest>()
                        .AddFilter<RequireAuthorizationRequestCachingEnabled>()
                        .UseSingletonHandler<RemoveCachedRequest>()
                        .SetOrder(int.MinValue + 100_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (string.IsNullOrEmpty(context.Request?.RequestId))
                    {
                        return default;
                    }

                    // Note: the ApplyAuthorizationResponse event is called for both successful
                    // and errored authorization responses but discrimination is not necessary here,
                    // as the authorization request must be removed from the distributed cache in both cases.

                    // Note: the cache key is always prefixed with a specific marker
                    // to avoid collisions with the other types of cached payloads.
                    return new ValueTask(_cache.RemoveAsync(Cache.AuthorizationRequest + context.Request.RequestId));
                }
            }

            /// <summary>
            /// Contains the logic responsible of processing authorization responses using the form_post response mode.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
            /// </summary>
            public class ProcessFormPostResponse : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
            {
                private readonly HtmlEncoder _encoder;

                public ProcessFormPostResponse(HtmlEncoder encoder)
                    => _encoder = encoder;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                        .AddFilter<RequireHttpRequest>()
                        .UseSingletonHandler<ProcessFormPostResponse>()
                        .SetOrder(50_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                    // this may indicate that the request was incorrectly processed by another server stack.
                    var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                    if (response is null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                    }

                    if (string.IsNullOrEmpty(context.RedirectUri) ||
                       !string.Equals(context.ResponseMode, ResponseModes.FormPost, StringComparison.Ordinal))
                    {
                        return;
                    }

                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6147), context.RedirectUri, context.Response);

                    using (var buffer = new MemoryStream())
                    using (var writer = new StreamWriter(buffer))
                    {
                        writer.WriteLine("<!doctype html>");
                        writer.WriteLine("<html>");
                        writer.WriteLine("<body>");

                        // While the redirect_uri parameter should be guarded against unknown values,
                        // it's still safer to encode it to avoid cross-site scripting attacks
                        // if the authorization server has a relaxed policy concerning redirect URIs.
                        writer.WriteLine($@"<form name=""form"" method=""post"" action=""{_encoder.Encode(context.RedirectUri)}"">");

                        // Note: while initially not allowed by the core OAuth 2.0 specification, multiple parameters
                        // with the same name are used by derived drafts like the OAuth 2.0 token exchange specification.
                        // For consistency, multiple parameters with the same name are also supported by this endpoint.
                        foreach (var (key, value) in
                            from parameter in context.Response.GetParameters()
                            let values = (string?[]?) parameter.Value
                            where values is not null
                            from value in values
                            where !string.IsNullOrEmpty(value)
                            select (parameter.Key, Value: value))
                        {
                            writer.WriteLine($@"<input type=""hidden"" name=""{_encoder.Encode(key)}"" value=""{_encoder.Encode(value)}"" />");
                        }

                        writer.WriteLine(@"<noscript>Click here to finish the authorization process: <input type=""submit"" /></noscript>");
                        writer.WriteLine("</form>");
                        writer.WriteLine("<script>document.form.submit();</script>");
                        writer.WriteLine("</body>");
                        writer.WriteLine("</html>");
                        writer.Flush();

                        response.StatusCode = 200;
                        response.ContentLength = buffer.Length;
                        response.ContentType = "text/html;charset=UTF-8";

                        response.Headers["Cache-Control"] = "no-cache";
                        response.Headers["Pragma"] = "no-cache";
                        response.Headers["Expires"] = "-1";

                        buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                        await buffer.CopyToAsync(response.Body, 4096);
                    }

                    context.HandleRequest();
                }
            }

            /// <summary>
            /// Contains the logic responsible of processing authorization responses using the query response mode.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
            /// </summary>
            public class ProcessQueryResponse : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                        .AddFilter<RequireHttpRequest>()
                        .UseSingletonHandler<ProcessQueryResponse>()
                        .SetOrder(ProcessFormPostResponse.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                    // this may indicate that the request was incorrectly processed by another server stack.
                    var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                    if (response is null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                    }

                    if (string.IsNullOrEmpty(context.RedirectUri) ||
                       !string.Equals(context.ResponseMode, ResponseModes.Query, StringComparison.Ordinal))
                    {
                        return default;
                    }

                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6148), context.RedirectUri, context.Response);

                    // Note: while initially not allowed by the core OAuth 2.0 specification, multiple parameters
                    // with the same name are used by derived drafts like the OAuth 2.0 token exchange specification.
                    // For consistency, multiple parameters with the same name are also supported by this endpoint.

#if SUPPORTS_MULTIPLE_VALUES_IN_QUERYHELPERS
                    var location = QueryHelpers.AddQueryString(context.RedirectUri,
                        from parameter in context.Response.GetParameters()
                        let values = (string?[]?) parameter.Value
                        where values is not null
                        from value in values
                        where !string.IsNullOrEmpty(value)
                        select KeyValuePair.Create(parameter.Key, value));
#else
                    var location = context.RedirectUri;

                    foreach (var (key, value) in
                        from parameter in context.Response.GetParameters()
                        let values = (string?[]?) parameter.Value
                        where values is not null
                        from value in values
                        where !string.IsNullOrEmpty(value)
                        select (parameter.Key, Value: value))
                    {
                        location = QueryHelpers.AddQueryString(location, key, value);
                    }
#endif
                    response.Redirect(location);
                    context.HandleRequest();

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of processing authorization responses using the fragment response mode.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
            /// </summary>
            public class ProcessFragmentResponse : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                        .AddFilter<RequireHttpRequest>()
                        .UseSingletonHandler<ProcessFragmentResponse>()
                        .SetOrder(ProcessQueryResponse.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                    // this may indicate that the request was incorrectly processed by another server stack.
                    var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                    if (response is null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                    }

                    if (string.IsNullOrEmpty(context.RedirectUri) ||
                       !string.Equals(context.ResponseMode, ResponseModes.Fragment, StringComparison.Ordinal))
                    {
                        return default;
                    }

                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6149), context.RedirectUri, context.Response);

                    var builder = new StringBuilder(context.RedirectUri);

                    // Note: while initially not allowed by the core OAuth 2.0 specification, multiple parameters
                    // with the same name are used by derived drafts like the OAuth 2.0 token exchange specification.
                    // For consistency, multiple parameters with the same name are also supported by this endpoint.
                    foreach (var (key, value) in
                        from parameter in context.Response.GetParameters()
                        let values = (string?[]?) parameter.Value
                        where values is not null
                        from value in values
                        where !string.IsNullOrEmpty(value)
                        select (parameter.Key, Value: value))
                    {
                        builder.Append(Contains(builder, '#') ? '&' : '#')
                               .Append(Uri.EscapeDataString(key))
                               .Append('=')
                               .Append(Uri.EscapeDataString(value));
                    }

                    response.Redirect(builder.ToString());
                    context.HandleRequest();

                    return default;

                    static bool Contains(StringBuilder builder, char delimiter)
                    {
                        for (var index = 0; index < builder.Length; index++)
                        {
                            if (builder[index] == delimiter)
                            {
                                return true;
                            }
                        }

                        return false;
                    }
                }
            }
        }
    }
}
