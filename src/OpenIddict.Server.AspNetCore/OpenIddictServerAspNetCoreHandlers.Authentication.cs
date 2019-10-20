/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreHandlerFilters;
using static OpenIddict.Server.OpenIddictServerEvents;

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
                ProcessFormPostResponse.Descriptor,
                ProcessQueryResponse.Descriptor,
                ProcessFragmentResponse.Descriptor,
                ProcessStatusCodePagesErrorResponse<ApplyAuthorizationResponseContext>.Descriptor,
                ProcessPassthroughErrorResponse<ApplyAuthorizationResponseContext, RequireAuthorizationEndpointPassthroughEnabled>.Descriptor,
                ProcessLocalErrorResponse<ApplyAuthorizationResponseContext>.Descriptor);

            /// <summary>
            /// Contains the logic responsible of restoring cached requests from the request_id, if specified.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
            /// </summary>
            public class RestoreCachedRequestParameters : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
            {
                private readonly IDistributedCache _cache;

                public RestoreCachedRequestParameters() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("A distributed cache instance must be registered when enabling request caching.")
                    .Append("To register the default in-memory distributed cache implementation, reference the ")
                    .Append("'Microsoft.Extensions.Caching.Memory' package and call ")
                    .Append("'services.AddDistributedMemoryCache()' from 'ConfigureServices'.")
                    .ToString());

                public RestoreCachedRequestParameters([NotNull] IDistributedCache cache)
                    => _cache = cache;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
                        .AddFilter<RequireHttpRequest>()
                        .AddFilter<RequireRequestCachingEnabled>()
                        .UseSingletonHandler<RestoreCachedRequestParameters>()
                        .SetOrder(ExtractGetOrPostRequest<ExtractAuthorizationRequestContext>.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ExtractAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // If a request_id parameter can be found in the authorization request,
                    // restore the complete authorization request from the distributed cache.

                    if (string.IsNullOrEmpty(context.Request.RequestId))
                    {
                        return;
                    }

                    // Note: the cache key is always prefixed with a specific marker
                    // to avoid collisions with the other types of cached payloads.
                    var payload = await _cache.GetAsync(Cache.AuthorizationRequest + context.Request.RequestId);
                    if (payload == null)
                    {
                        context.Logger.LogError("The authorization request was rejected because an unknown " +
                                                "or invalid request_id parameter was specified.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The specified 'request_id' parameter is invalid.");

                        return;
                    }

                    // Restore the authorization request parameters from the serialized payload.
                    using var reader = new BsonDataReader(new MemoryStream(payload));
                    foreach (var parameter in JObject.Load(reader))
                    {
                        // Avoid overriding the current request parameters.
                        if (context.Request.HasParameter(parameter.Key))
                        {
                            continue;
                        }

                        context.Request.SetParameter(parameter.Key, parameter.Value);
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

                public CacheRequestParameters() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("A distributed cache instance must be registered when enabling request caching.")
                    .Append("To register the default in-memory distributed cache implementation, reference the ")
                    .Append("'Microsoft.Extensions.Caching.Memory' package and call ")
                    .Append("'services.AddDistributedMemoryCache()' from 'ConfigureServices'.")
                    .ToString());

                public CacheRequestParameters(
                    [NotNull] IDistributedCache cache,
                    [NotNull] IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
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
                        .AddFilter<RequireRequestCachingEnabled>()
                        .UseSingletonHandler<CacheRequestParameters>()
                        .SetOrder(RestoreCachedRequestParameters.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ExtractAuthorizationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                    // this may indicate that the request was incorrectly processed by another server stack.
                    var request = context.Transaction.GetHttpRequest();
                    if (request == null)
                    {
                        throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
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
                    var stream = new MemoryStream();
                    using (var writer = new BsonDataWriter(stream))
                    {
                        writer.CloseOutput = false;

                        var serializer = JsonSerializer.CreateDefault();
                        serializer.Serialize(writer, context.Request);
                    }

                    // Note: the cache key is always prefixed with a specific marker
                    // to avoid collisions with the other types of cached payloads.
                    await _cache.SetAsync(Cache.AuthorizationRequest + context.Request.RequestId,
                        stream.ToArray(), _options.CurrentValue.RequestCachingPolicy);

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

                public RemoveCachedRequest() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("A distributed cache instance must be registered when enabling request caching.")
                    .Append("To register the default in-memory distributed cache implementation, reference the ")
                    .Append("'Microsoft.Extensions.Caching.Memory' package and call ")
                    .Append("'services.AddDistributedMemoryCache()' from 'ConfigureServices'.")
                    .ToString());

                public RemoveCachedRequest([NotNull] IDistributedCache cache)
                    => _cache = cache;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                        .AddFilter<RequireHttpRequest>()
                        .AddFilter<RequireRequestCachingEnabled>()
                        .UseSingletonHandler<RemoveCachedRequest>()
                        .SetOrder(ProcessFormPostResponse.Descriptor.Order - 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ApplyAuthorizationResponseContext context)
                {
                    if (context == null)
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

                public ProcessFormPostResponse([NotNull] HtmlEncoder encoder)
                    => _encoder = encoder;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                        .AddFilter<RequireHttpRequest>()
                        .UseSingletonHandler<ProcessFormPostResponse>()
                        .SetOrder(ProcessQueryResponse.Descriptor.Order - 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ApplyAuthorizationResponseContext context)
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
                        throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                    }

                    if (string.IsNullOrEmpty(context.RedirectUri) ||
                       !string.Equals(context.ResponseMode, ResponseModes.FormPost, StringComparison.Ordinal))
                    {
                        return;
                    }

                    context.Logger.LogInformation("The authorization response was successfully returned to " +
                                                  "'{RedirectUri}' using the form post response mode: {Response}.",
                                                  context.RedirectUri, context.Response);

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
                        foreach (var parameter in context.Response.GetFlattenedParameters())
                        {
                            var key = _encoder.Encode(parameter.Key);
                            var value = _encoder.Encode(parameter.Value);

                            writer.WriteLine($@"<input type=""hidden"" name=""{key}"" value=""{value}"" />");
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
                        .SetOrder(ProcessFragmentResponse.Descriptor.Order - 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ApplyAuthorizationResponseContext context)
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
                        throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                    }

                    if (string.IsNullOrEmpty(context.RedirectUri) ||
                       !string.Equals(context.ResponseMode, ResponseModes.Query, StringComparison.Ordinal))
                    {
                        return default;
                    }

                    context.Logger.LogInformation("The authorization response was successfully returned to " +
                                                  "'{RedirectUri}' using the query response mode: {Response}.",
                                                  context.RedirectUri, context.Response);

                    var location = context.RedirectUri;

                    // Note: while initially not allowed by the core OAuth 2.0 specification, multiple parameters
                    // with the same name are used by derived drafts like the OAuth 2.0 token exchange specification.
                    // For consistency, multiple parameters with the same name are also supported by this endpoint.
                    foreach (var parameter in context.Response.GetFlattenedParameters())
                    {
                        location = QueryHelpers.AddQueryString(location, parameter.Key, parameter.Value);
                    }

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
                        .SetOrder(ProcessLocalErrorResponse<ApplyAuthorizationResponseContext>.Descriptor.Order - 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ApplyAuthorizationResponseContext context)
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
                        throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                    }

                    if (string.IsNullOrEmpty(context.RedirectUri) ||
                       !string.Equals(context.ResponseMode, ResponseModes.Fragment, StringComparison.Ordinal))
                    {
                        return default;
                    }

                    context.Logger.LogInformation("The authorization response was successfully returned to " +
                                                  "'{RedirectUri}' using the fragment response mode: {Response}.",
                                                  context.RedirectUri, context.Response);

                    var builder = new StringBuilder(context.RedirectUri);

                    // Note: while initially not allowed by the core OAuth 2.0 specification, multiple parameters
                    // with the same name are used by derived drafts like the OAuth 2.0 token exchange specification.
                    // For consistency, multiple parameters with the same name are also supported by this endpoint.
                    foreach (var parameter in context.Response.GetFlattenedParameters())
                    {
                        builder.Append(Contains(builder, '#') ? '&' : '#')
                               .Append(Uri.EscapeDataString(parameter.Key))
                               .Append('=')
                               .Append(Uri.EscapeDataString(parameter.Value));
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
