/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using OpenIddict.Extensions;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpConstants;

namespace OpenIddict.Client.SystemNetHttp;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictClientSystemNetHttpHandlers
{
    public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; }
        = ImmutableArray.Create<OpenIddictClientHandlerDescriptor>()
            .AddRange(Discovery.DefaultHandlers)
            .AddRange(Exchange.DefaultHandlers)
            .AddRange(Userinfo.DefaultHandlers);

    /// <summary>
    /// Contains the logic responsible for preparing an HTTP GET request message.
    /// </summary>
    public sealed class PrepareGetHttpRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<PrepareGetHttpRequest<TContext>>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Store the HttpRequestMessage in the transaction properties.
            context.Transaction.SetProperty(typeof(HttpRequestMessage).FullName!,
                new HttpRequestMessage(HttpMethod.Get, context.Address));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing an HTTP POST request message.
    /// </summary>
    public sealed class PreparePostHttpRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<PreparePostHttpRequest<TContext>>()
                .SetOrder(PrepareGetHttpRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Store the HttpRequestMessage in the transaction properties.
            context.Transaction.SetProperty(typeof(HttpRequestMessage).FullName!,
                new HttpRequestMessage(HttpMethod.Post, context.Address));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the appropriate HTTP
    /// Accept-* headers to the HTTP request message to receive JSON responses.
    /// </summary>
    public sealed class AttachJsonAcceptHeaders<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<AttachJsonAcceptHeaders<TContext>>()
                .SetOrder(PreparePostHttpRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(MediaTypes.Json));
            request.Headers.AcceptCharset.Add(new StringWithQualityHeaderValue(Charsets.Utf8));

            // Note: for security reasons, HTTP compression is never opted-in by default. Providers
            // that require using HTTP compression that register a custom event handler to send an
            // Accept-Encoding header containing the supported algorithms (e.g GZip/Deflate/Brotli).

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the user agent to the HTTP request.
    /// </summary>
    public sealed class AttachUserAgentHeader<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        private readonly IOptionsMonitor<OpenIddictClientSystemNetHttpOptions> _options;

        public AttachUserAgentHeader(IOptionsMonitor<OpenIddictClientSystemNetHttpOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<AttachUserAgentHeader<TContext>>()
                .SetOrder(AttachJsonAcceptHeaders<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            // Some authorization servers are known to aggressively check user agents and encourage
            // developers to use unique user agents. While a default user agent is always added,
            // the default value doesn't differ accross applications. To reduce the risks of seeing
            // requests blocked, a more specific user agent header can be configured by the developer.
            // In this case, the value specified by the developer always appears first in the list.
            if (_options.CurrentValue.ProductInformation is ProductInfoHeaderValue information)
            {
                request.Headers.UserAgent.Add(information);
            }

            // Attach a user agent based on the assembly version of the System.Net.Http integration.
            var assembly = typeof(OpenIddictClientSystemNetHttpHandlers).Assembly.GetName();
            request.Headers.UserAgent.Add(new ProductInfoHeaderValue(
                productName: assembly.Name!,
                productVersion: assembly.Version!.ToString()));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the query string parameters to the HTTP request.
    /// </summary>
    public sealed class AttachQueryStringParameters<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<AttachQueryStringParameters<TContext>>()
                .SetOrder(AttachFormParameters<TContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            if (request.RequestUri is null || context.Transaction.Request.Count is 0)
            {
                return default;
            }

            request.RequestUri = OpenIddictHelpers.AddQueryStringParameters(request.RequestUri,
                context.Transaction.Request.GetParameters().ToDictionary(
                    parameter => parameter.Key,
                    parameter => new StringValues((string?[]?) parameter.Value)));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the form parameters to the HTTP request.
    /// </summary>
    public sealed class AttachFormParameters<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<AttachFormParameters<TContext>>()
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

            Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            request.Content = new FormUrlEncodedContent(
                from parameter in context.Transaction.Request.GetParameters()
                let values = (string?[]?) parameter.Value
                where values is not null
                from value in values
                select new KeyValuePair<string?, string?>(parameter.Key, value));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for sending the HTTP request to the remote server.
    /// </summary>
    public sealed class SendHttpRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        private readonly IHttpClientFactory _factory;

        public SendHttpRequest(IHttpClientFactory factory)
            => _factory = factory ?? throw new ArgumentNullException(nameof(factory));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<SendHttpRequest<TContext>>()
                .SetOrder(DecompressResponseContent<TContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            var assembly = typeof(OpenIddictClientSystemNetHttpOptions).Assembly.GetName();
            using var client = _factory.CreateClient(assembly.Name!) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0174));

#if SUPPORTS_HTTP_CLIENT_DEFAULT_REQUEST_VERSION
            // If supported, import the HTTP version from the client instance.
            request.Version = client.DefaultRequestVersion;
#endif

#if SUPPORTS_HTTP_CLIENT_DEFAULT_REQUEST_VERSION_POLICY
            // If supported, import the HTTP version policy from the client instance.
            request.VersionPolicy = client.DefaultVersionPolicy;
#endif
            HttpResponseMessage response;

            try
            {
                // Note: HttpCompletionOption.ResponseContentRead is deliberately used to force the
                // response stream to be buffered so that can it can be read multiple times if needed
                // (e.g if the JSON deserialization process fails, the stream is read as a string
                // during a second pass a second time for logging/debuggability purposes).
                response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead);
            }

            // If an exception is thrown at this stage, this likely means a persistent network error occurred.
            // In this case, log the error details and return a generic error to stop processing the event.
            catch (Exception exception)
            {
                context.Logger.LogError(exception, SR.GetResourceString(SR.ID6182));

                context.Reject(
                    error: Errors.ServerError,
                    description: SR.GetResourceString(SR.ID2136),
                    uri: SR.FormatID8000(SR.ID2136));

                return;
            }

            // Store the HttpResponseMessage in the transaction properties.
            context.Transaction.SetProperty(typeof(HttpResponseMessage).FullName!, response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0175)));
        }
    }

    /// <summary>
    /// Contains the logic responsible for disposing of the HTTP request message.
    /// </summary>
    public sealed class DisposeHttpRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<DisposeHttpRequest<TContext>>()
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

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            request.Dispose();

            // Remove the request from the transaction properties.
            context.Transaction.SetProperty<HttpRequestMessage>(typeof(HttpRequestMessage).FullName!, null);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for decompressing the returned HTTP content.
    /// </summary>
    public sealed class DecompressResponseContent<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<DecompressResponseContent<TContext>>()
                .SetOrder(ExtractJsonHttpResponse<TContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: automatic content decompression can be enabled by constructing an HttpClient wrapping
            // a generic HttpClientHandler, a SocketsHttpHandler or a WinHttpHandler instance with the
            // AutomaticDecompression property set to the desired algorithms (e.g GZip, Deflate or Brotli).
            //
            // Unfortunately, while convenient and efficient, relying on this property has two downsides:
            //
            //   - By being specific to HttpClientHandler/SocketsHttpHandler/WinHttpHandler, the automatic
            //     decompression feature cannot be used with any other type of client handler, forcing users
            //     to use a specific instance configured with decompression support enforced and preventing
            //     them from chosing their own implementation (e.g via ConfigurePrimaryHttpMessageHandler()).
            //
            //   - Setting AutomaticDecompression always overrides the Accept-Encoding header of all requests
            //     to include the selected algorithms without offering a way to make this behavior opt-in.
            //     Sadly, using HTTP content compression with transport security enabled has security implications
            //     that could potentially lead to compression side-channel attacks if the client is used with
            //     remote endpoints that reflect user-defined data and contain secret values (e.g BREACH attacks).
            //
            // Since OpenIddict itself cannot safely assume such scenarios will never happen (e.g a token request
            // will typically be sent with an authorization code that can be defined by a malicious user and can
            // potentially be reflected in the token response depending on the configuration of the remote server),
            // it is safer to disable compression by default by not sending an Accept-Encoding header while
            // still allowing encoded responses to be processed (e.g StackExchange forces content compression
            // for all the supported HTTP APIs even if no Accept-Encoding header is explicitly sent by the client).
            //
            // For these reasons, OpenIddict doesn't rely on the automatic decompression feature and uses
            // a custom event handler to deal with GZip/Deflate/Brotli-encoded responses, so that providers
            // that require using HTTP compression can be supported without having to use it for all providers.

            // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var response = context.Transaction.GetHttpResponseMessage() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            // If no Content-Encoding header was returned, keep the response stream as-is.
            if (response.Content is not { Headers.ContentEncoding.Count: > 0 })
            {
                return;
            }

            Stream? stream = null;

            // Iterate the returned encodings and wrap the response stream using the specified algorithm.
            // If one of the returned algorithms cannot be recognized, immediately return an error.
            foreach (var encoding in response.Content.Headers.ContentEncoding.Reverse())
            {
                if (string.Equals(encoding, ContentEncodings.Identity, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                else if (string.Equals(encoding, ContentEncodings.Gzip, StringComparison.OrdinalIgnoreCase))
                {
                    stream ??= await response.Content.ReadAsStreamAsync();
                    stream = new GZipStream(stream, CompressionMode.Decompress);
                }

#if SUPPORTS_ZLIB_COMPRESSION
                // Note: some server implementations are known to incorrectly implement the "Deflate" compression
                // algorithm and don't wrap the compressed data in a ZLib frame as required by the specifications.
                //
                // Such implementations are deliberately not supported here. In this case, it is recommended to avoid
                // including "deflate" in the Accept-Encoding header if the server is known to be non-compliant.
                //
                // For more information, read https://www.rfc-editor.org/rfc/rfc9110.html#name-deflate-coding.
                else if (string.Equals(encoding, ContentEncodings.Deflate, StringComparison.OrdinalIgnoreCase))
                {
                    stream ??= await response.Content.ReadAsStreamAsync();
                    stream = new ZLibStream(stream, CompressionMode.Decompress);
                }
#endif
#if SUPPORTS_BROTLI_COMPRESSION
                else if (string.Equals(encoding, ContentEncodings.Brotli, StringComparison.OrdinalIgnoreCase))
                {
                    stream ??= await response.Content.ReadAsStreamAsync();
                    stream = new BrotliStream(stream, CompressionMode.Decompress);
                }
#endif
                else
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2143),
                        uri: SR.FormatID8000(SR.ID2143));

                    return;
                }
            }

            // At this point, if the stream was wrapped, replace the content attached
            // to the HTTP response message to use the specified stream transformations.
            if (stream is not null)
            {
                // Note: StreamContent.LoadIntoBufferAsync is deliberately used to force the stream
                // content to be buffered so that can it can be read multiple times if needed
                // (e.g if the JSON deserialization process fails, the stream is read as a string
                // during a second pass a second time for logging/debuggability purposes).
                var content = new StreamContent(stream);
                await content.LoadIntoBufferAsync();

                // Copy the headers from the original content to the new instance.
                foreach (var header in response.Content.Headers)
                {
                    content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }

                // Reset the Content-Length and Content-Encoding headers to indicate
                // the content was successfully decoded using the specified algorithms.
                content.Headers.ContentLength = null;
                content.Headers.ContentEncoding.Clear();

                response.Content = content;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting the response from the JSON-encoded HTTP body.
    /// </summary>
    public sealed class ExtractJsonHttpResponse<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<ExtractJsonHttpResponse<TContext>>()
                .SetOrder(ExtractWwwAuthenticateHeader<TContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Don't overwrite the response if one was already provided.
            if (context.Transaction.Response is not null)
            {
                return;
            }

            // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var response = context.Transaction.GetHttpResponseMessage() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            // If the returned Content-Type doesn't indicate the response has a JSON payload,
            // ignore it and allow other handlers in the pipeline to process the HTTP response.
            if (!string.Equals(response.Content.Headers.ContentType?.MediaType,
                MediaTypes.Json, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            try
            {
                // Note: ReadFromJsonAsync() automatically validates the content encoding and transparently
                // transcodes the response stream if a non-UTF-8 response is returned by the remote server.
                context.Transaction.Response = await response.Content.ReadFromJsonAsync<OpenIddictResponse>();
            }

            // If an exception is thrown at this stage, this likely means the returned response was not a valid
            // JSON response or was not correctly formatted as a JSON object. This typically happens when
            // a server error occurs while the JSON response is being generated and returned to the client.
            catch (Exception exception)
            {
                context.Logger.LogError(exception, SR.GetResourceString(SR.ID6183),
                    await response.Content.ReadAsStringAsync());

                context.Reject(
                    error: Errors.ServerError,
                    description: SR.GetResourceString(SR.ID2137),
                    uri: SR.FormatID8000(SR.ID2137));

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting errors from WWW-Authenticate headers.
    /// </summary>
    public sealed class ExtractWwwAuthenticateHeader<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<ExtractWwwAuthenticateHeader<TContext>>()
                .SetOrder(ValidateHttpResponse<TContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Don't overwrite the response if one was already provided.
            if (context.Transaction.Response is not null)
            {
                return default;
            }

            // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var response = context.Transaction.GetHttpResponseMessage() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            if (response.Headers.WwwAuthenticate.Count is 0)
            {
                return default;
            }

            var parameters = new Dictionary<string, StringValues>(response.Headers.WwwAuthenticate.Count);

            foreach (var header in response.Headers.WwwAuthenticate)
            {
                if (string.IsNullOrEmpty(header.Parameter))
                {
                    continue;
                }

                // Note: while initially not allowed by the core OAuth 2.0 specification, multiple
                // parameters with the same name are used by derived drafts like the OAuth 2.0
                // token exchange specification. For consistency, multiple parameters with the
                // same name are also supported when returned as part of WWW-Authentication headers.

                foreach (var parameter in header.Parameter.Split(Separators.Comma, StringSplitOptions.RemoveEmptyEntries))
                {
                    var values = parameter.Split(Separators.EqualsSign, StringSplitOptions.RemoveEmptyEntries);
                    if (values.Length is not 2)
                    {
                        continue;
                    }

                    var (name, value) = (
                        values[0]?.Trim(Separators.Space[0]),
                        values[1]?.Trim(Separators.Space[0], Separators.DoubleQuote[0]));

                    if (string.IsNullOrEmpty(name))
                    {
                        continue;
                    }

                    parameters[name] = parameters.ContainsKey(name) ?
                        StringValues.Concat(parameters[name], value?.Replace("\\\"", "\"")) :
                        new StringValues(value?.Replace("\\\"", "\""));
                }
            }

            context.Transaction.Response = new OpenIddictResponse(parameters);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting errors from WWW-Authenticate headers.
    /// </summary>
    public sealed class ValidateHttpResponse<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<ValidateHttpResponse<TContext>>()
                .SetOrder(DisposeHttpResponse<TContext>.Descriptor.Order - 50_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var response = context.Transaction.GetHttpResponseMessage() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            // At this stage, return a generic error based on the HTTP status code if no
            // error could be extracted from the payload or from the WWW-Authenticate header.
            if (!response.IsSuccessStatusCode && string.IsNullOrEmpty(context.Transaction.Response?.Error))
            {
                context.Logger.LogError(SR.GetResourceString(SR.ID6184), response.StatusCode,
                    await response.Content.ReadAsStringAsync());

                context.Reject(
                    error: (int) response.StatusCode switch
                    {
                        400 => Errors.InvalidRequest,
                        401 => Errors.InvalidToken,
                        403 => Errors.InsufficientAccess,
                        429 => Errors.SlowDown,
                        500 => Errors.ServerError,
                        503 => Errors.TemporarilyUnavailable,
                        _   => Errors.ServerError
                    },
                    description: SR.FormatID2161((int) response.StatusCode),
                    uri: SR.FormatID8000(SR.ID2161));

                return;
            }

            // If no other event handler was able to extract the response payload at this point
            // (e.g because an unsupported content type was returned), return a generic error.
            if (context.Transaction.Response is null)
            {
                context.Logger.LogError(SR.GetResourceString(SR.ID6185), response.StatusCode,
                    response.Content.Headers.ContentType, await response.Content.ReadAsStringAsync());

                context.Reject(
                    error: Errors.ServerError,
                    description: SR.GetResourceString(SR.ID2162),
                    uri: SR.FormatID8000(SR.ID2162));

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for disposing of the HTTP response message.
    /// </summary>
    public sealed class DisposeHttpResponse<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<DisposeHttpResponse<TContext>>()
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

            // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var response = context.Transaction.GetHttpResponseMessage() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            response.Dispose();

            // Remove the response from the transaction properties.
            context.Transaction.SetProperty<HttpResponseMessage>(typeof(HttpResponseMessage).FullName!, null);

            return default;
        }
    }
}
