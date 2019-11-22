/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Newtonsoft.Json.Linq;
using Owin;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.Owin.OpenIddictServerOwinConstants;
using static OpenIddict.Server.Owin.OpenIddictServerOwinHandlerFilters;

namespace OpenIddict.Server.Owin
{
    public static partial class OpenIddictServerOwinHandlers
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
                EnablePassthroughMode<HandleUserinfoRequestContext, RequireLogoutEndpointPassthroughEnabled>.Descriptor,

                /*
                 * Logout response processing:
                 */
                RemoveCachedRequest.Descriptor,
                ProcessQueryResponse.Descriptor,
                ProcessHostRedirectionResponse<ApplyVerificationResponseContext>.Descriptor,
                ProcessPassthroughErrorResponse<ApplyLogoutResponseContext, RequireLogoutEndpointPassthroughEnabled>.Descriptor,
                ProcessLocalErrorResponse<ApplyLogoutResponseContext>.Descriptor,
                ProcessEmptyResponse<ApplyLogoutResponseContext>.Descriptor);

            /// <summary>
            /// Contains the logic responsible of restoring cached requests from the request_id, if specified.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
            /// </summary>
            public class RestoreCachedRequestParameters : IOpenIddictServerHandler<ExtractLogoutRequestContext>
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
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractLogoutRequestContext>()
                        .AddFilter<RequireOwinRequest>()
                        .AddFilter<RequireLogoutEndpointCachingEnabled>()
                        .UseSingletonHandler<RestoreCachedRequestParameters>()
                        .SetOrder(ExtractGetOrPostRequest<ExtractLogoutRequestContext>.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ExtractLogoutRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // If a request_id parameter can be found in the logout request,
                    // restore the complete logout request from the distributed cache.

                    if (string.IsNullOrEmpty(context.Request.RequestId))
                    {
                        return;
                    }

                    // Note: the cache key is always prefixed with a specific marker
                    // to avoid collisions with the other types of cached payloads.
                    var payload = await _cache.GetAsync(Cache.LogoutRequest + context.Request.RequestId);
                    if (payload == null)
                    {
                        context.Logger.LogError("The logout request was rejected because an unknown " +
                                                "or invalid request_id parameter was specified.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The specified 'request_id' parameter is invalid.");

                        return;
                    }

                    // Restore the logout request parameters from the serialized payload.
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
            /// Contains the logic responsible of caching logout requests, if applicable.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
            /// </summary>
            public class CacheRequestParameters : IOpenIddictServerHandler<ExtractLogoutRequestContext>
            {
                private readonly IDistributedCache _cache;
                private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

                public CacheRequestParameters() => throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("A distributed cache instance must be registered when enabling request caching.")
                    .Append("To register the default in-memory distributed cache implementation, reference the ")
                    .Append("'Microsoft.Extensions.Caching.Memory' package and call ")
                    .Append("'services.AddDistributedMemoryCache()' from 'ConfigureServices'.")
                    .ToString());

                public CacheRequestParameters(
                    [NotNull] IDistributedCache cache,
                    [NotNull] IOptionsMonitor<OpenIddictServerOwinOptions> options)
                {
                    _cache = cache;
                    _options = options;
                }

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractLogoutRequestContext>()
                        .AddFilter<RequireOwinRequest>()
                        .AddFilter<RequireLogoutEndpointCachingEnabled>()
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
                public async ValueTask HandleAsync([NotNull] ExtractLogoutRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                    // this may indicate that the request was incorrectly processed by another server stack.
                    var request = context.Transaction.GetOwinRequest();
                    if (request == null)
                    {
                        throw new InvalidOperationException("The OWIN request cannot be resolved.");
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
                    using var generator = RandomNumberGenerator.Create();
                    generator.GetBytes(data);

                    context.Request.RequestId = Base64UrlEncoder.Encode(data);

                    // Store the serialized logout request parameters in the distributed cache.
                    var stream = new MemoryStream();
                    using (var writer = new BsonDataWriter(stream))
                    {
                        writer.CloseOutput = false;

                        var serializer = JsonSerializer.CreateDefault();
                        serializer.Serialize(writer, context.Request);
                    }

                    // Note: the cache key is always prefixed with a specific marker
                    // to avoid collisions with the other types of cached payloads.
                    await _cache.SetAsync(Cache.LogoutRequest + context.Request.RequestId,
                        stream.ToArray(), _options.CurrentValue.LogoutEndpointCachingPolicy);

                    // Create a new GET logout request containing only the request_id parameter.
                    var address = WebUtilities.AddQueryString(
                        uri: request.Scheme + "://" + request.Host + request.PathBase + request.Path,
                        name: Parameters.RequestId,
                        value: context.Request.RequestId);

                    request.Context.Response.Redirect(address);

                    // Mark the response as handled to skip the rest of the pipeline.
                    context.HandleRequest();
                }
            }

            /// <summary>
            /// Contains the logic responsible of removing cached logout requests from the distributed cache.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
            /// </summary>
            public class RemoveCachedRequest : IOpenIddictServerHandler<ApplyLogoutResponseContext>
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
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyLogoutResponseContext>()
                        .AddFilter<RequireOwinRequest>()
                        .AddFilter<RequireLogoutEndpointCachingEnabled>()
                        .UseSingletonHandler<RemoveCachedRequest>()
                        .SetOrder(ProcessQueryResponse.Descriptor.Order - 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ApplyLogoutResponseContext context)
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
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
            /// </summary>
            public class ProcessQueryResponse : IOpenIddictServerHandler<ApplyLogoutResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyLogoutResponseContext>()
                        .AddFilter<RequireOwinRequest>()
                        .UseSingletonHandler<ProcessQueryResponse>()
                        .SetOrder(ProcessPassthroughErrorResponse<ApplyLogoutResponseContext, IOpenIddictServerHandlerFilter<ApplyLogoutResponseContext>>.Descriptor.Order - 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ApplyLogoutResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                    // this may indicate that the request was incorrectly processed by another server stack.
                    var response = context.Transaction.GetOwinRequest()?.Context.Response;
                    if (response == null)
                    {
                        throw new InvalidOperationException("The OWIN request cannot be resolved.");
                    }

                    if (string.IsNullOrEmpty(context.PostLogoutRedirectUri))
                    {
                        return default;
                    }

                    context.Logger.LogInformation("The logout response was successfully returned to '{PostLogoutRedirectUri}': {Response}.",
                                                  context.PostLogoutRedirectUri, response);

                    var location = context.PostLogoutRedirectUri;

                    // Note: while initially not allowed by the core OAuth 2.0 specification, multiple parameters
                    // with the same name are used by derived drafts like the OAuth 2.0 token exchange specification.
                    // For consistency, multiple parameters with the same name are also supported by this endpoint.
                    foreach (var (key, value) in
                        from parameter in context.Response.GetParameters()
                        let values = (string[]) parameter.Value
                        where values != null
                        from value in values
                        select (parameter.Key, Value: value))
                    {
                        location = WebUtilities.AddQueryString(location, key, value);
                    }

                    response.Redirect(location);
                    context.HandleRequest();

                    return default;
                }
            }
        }
    }
}
