/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpConstants;

namespace OpenIddict.Client.SystemNetHttp;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictClientSystemNetHttpHandlers
{
    public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } =
    [
        .. Authorization.DefaultHandlers,
        .. Device.DefaultHandlers,
        .. Discovery.DefaultHandlers,
        .. Exchange.DefaultHandlers,
        .. Introspection.DefaultHandlers,
        .. Revocation.DefaultHandlers,
        .. UserInfo.DefaultHandlers
    ];

    /// <summary>
    /// Contains the logic responsible for creating and attaching a <see cref="HttpClient"/>.
    /// </summary>
    public sealed class CreateHttpClient<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        private readonly IHttpClientFactory _factory;

        public CreateHttpClient(IHttpClientFactory factory)
            => _factory = factory ?? throw new ArgumentNullException(nameof(factory));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<CreateHttpClient<TContext>>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // Note: HttpClientFactory doesn't support flowing a list of properties that can be
            // accessed from the HttpClientAction or HttpMessageHandlerBuilderAction delegates
            // to dynamically amend the resulting HttpClient or HttpClientHandler instance.
            //
            // To work around this limitation, the OpenIddict System.Net.Http integration uses
            // an async-local context to flow per-instance properties and uses dynamic client
            // names to ensure the inner HttpClientHandler is not reused if the context differs.

            if (OpenIddictClientSystemNetHttpContext.Current is not null)
            {
                throw new InvalidOperationException(SR.FormatID0515(nameof(OpenIddictClientSystemNetHttpContext)));
            }

            try
            {
                OpenIddictClientSystemNetHttpContext.Current = new()
                {
                    Registration = context.Registration,
                    LocalCertificate = context.LocalCertificate
                };

                // Generate a stable identifier representing the current context to ensure the inner
                // HttpClientHandler instances are not reused for different operations if the properties
                // attached to the context are not identical (e.g different TLS client certificates).
                var identifier = OpenIddictClientSystemNetHttpContext.ComputeStableId(OpenIddictClientSystemNetHttpContext.Current);

                var client = _factory.CreateClient(
                    $"{typeof(OpenIddictClientSystemNetHttpOptions).Assembly.GetName().Name}:{identifier}")
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0174));

                // Create and store the HttpClient in the transaction properties.
                context.Transaction.SetProperty(typeof(HttpClient).FullName!, client);
            }

            finally
            {
                OpenIddictClientSystemNetHttpContext.Current = null;
            }

            return ValueTask.CompletedTask;
        }
    }

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
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<PrepareGetHttpRequest<TContext>>()
                .SetOrder(CreateHttpClient<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // Store the HttpRequestMessage in the transaction properties.
            context.Transaction.SetProperty(typeof(HttpRequestMessage).FullName!,
                new HttpRequestMessage(HttpMethod.Get, context.RemoteUri));

            return ValueTask.CompletedTask;
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
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<PreparePostHttpRequest<TContext>>()
                .SetOrder(PrepareGetHttpRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // Store the HttpRequestMessage in the transaction properties.
            context.Transaction.SetProperty(typeof(HttpRequestMessage).FullName!,
                new HttpRequestMessage(HttpMethod.Post, context.RemoteUri));

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the HTTP version to the HTTP request message.
    /// </summary>
    public sealed class AttachHttpVersion<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<AttachHttpVersion<TContext>>()
                .SetOrder(PreparePostHttpRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

#if NET
            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            var client = context.Transaction.GetHttpClient()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0372));

            // When supported, import the HTTP version and version policy from the client instance.
            request.Version = client.DefaultRequestVersion;
            request.VersionPolicy = client.DefaultVersionPolicy;
#endif
            return ValueTask.CompletedTask;
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
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<AttachJsonAcceptHeaders<TContext>>()
                .SetOrder(AttachHttpVersion<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(MediaTypes.Json));
            request.Headers.AcceptCharset.Add(new StringWithQualityHeaderValue(Charsets.Utf8));

            // Note: for security reasons, HTTP compression is never opted-in by default. Providers
            // that require using HTTP compression can register a custom event handler to send an
            // Accept-Encoding header containing the supported algorithms (e.g GZip/Deflate/Brotli).

            return ValueTask.CompletedTask;
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
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<AttachUserAgentHeader<TContext>>()
                .SetOrder(AttachJsonAcceptHeaders<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

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

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the contact address to the HTTP request.
    /// </summary>
    public sealed class AttachFromHeader<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        private readonly IOptionsMonitor<OpenIddictClientSystemNetHttpOptions> _options;

        public AttachFromHeader(IOptionsMonitor<OpenIddictClientSystemNetHttpOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<AttachFromHeader<TContext>>()
                .SetOrder(AttachUserAgentHeader<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            // Attach the contact address specified in the options, if available.
            request.Headers.From = _options.CurrentValue.ContactAddress?.ToString();

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the client credentials to the HTTP Authorization header.
    /// </summary>
    public sealed class AttachBasicAuthenticationCredentials<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<AttachBasicAuthenticationCredentials<TContext>>()
                .SetOrder(AttachHttpParameters<TContext>.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            // Note: don't overwrite the authorization header if one was already set by another handler.
            if (request.Headers.Authorization is null &&
                context.ClientAuthenticationMethod is ClientAuthenticationMethods.ClientSecretBasic &&
                !string.IsNullOrEmpty(context.Transaction.Request.ClientId))
            {
                // Important: the credentials MUST be formURL-encoded before being base64-encoded.
                var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(new StringBuilder()
                    .Append(EscapeDataString(context.Transaction.Request.ClientId))
                    .Append(':')
                    .Append(EscapeDataString(context.Transaction.Request.ClientSecret))
                    .ToString()));

                // Attach the authorization header containing the client credentials to the HTTP request.
                request.Headers.Authorization = new AuthenticationHeaderValue(Schemes.Basic, credentials);

                // Remove the client credentials from the request payload to ensure they are not sent twice.
                context.Transaction.Request.ClientId = context.Transaction.Request.ClientSecret = null;
            }

            return ValueTask.CompletedTask;

            static string? EscapeDataString(string? value)
                => value is not null ? Uri.EscapeDataString(value).Replace("%20", "+", StringComparison.Ordinal) : null;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters to the HTTP request.
    /// </summary>
    public sealed class AttachHttpParameters<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<AttachHttpParameters<TContext>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            if (context.Transaction.Request.Count is 0)
            {
                return ValueTask.CompletedTask;
            }

            // For GET requests, attach the request parameters to the query string by default.
            if (request.Method == HttpMethod.Get && request.RequestUri is not null)
            {
                request.RequestUri = OpenIddictHelpers.AddQueryStringParameters(request.RequestUri,
                    context.Transaction.Request.GetParameters().ToDictionary(
                        static parameter => parameter.Key,
                        static parameter => (StringValues) parameter.Value,
                        StringComparer.Ordinal));
            }

            // For POST requests, attach the request parameters to the request form by default.
            else if (request.Method == HttpMethod.Post)
            {
                request.Content = new FormUrlEncodedContent(
                    from parameter in context.Transaction.Request.GetParameters()
                    let values = (ImmutableArray<string?>?) parameter.Value
                    where values is not null
                    from value in values.GetValueOrDefault()
                    select KeyValuePair.Create(parameter.Key, value));
            }

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for sending the HTTP request to the remote server.
    /// </summary>
    public sealed class SendHttpRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<SendHttpRequest<TContext>>()
                .SetOrder(DecompressResponseContent<TContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            // Note: a "using" statement is deliberately used here to dispose of the client in this handler.
            using var client = context.Transaction.GetHttpClient()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0372));

            HttpResponseMessage response;

            try
            {
                // Note: HttpCompletionOption.ResponseContentRead is deliberately used to force the
                // response stream to be buffered so that can it can be read multiple times if needed
                // (e.g if the JSON deserialization process fails, the stream is read as a string
                // during a second pass a second time for logging/debuggability purposes).
                response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, context.CancellationToken);
            }

            // If an exception is thrown at this stage, this likely means a persistent network error occurred.
            // In this case, log the error details and return a generic error to stop processing the event.
            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                context.Logger.LogError(6182, exception, SR.GetResourceString(SR.ID6182));

                context.Reject(
                    error: Errors.ServerError,
                    description: SR.GetResourceString(SR.ID2136),
                    uri: SR.FormatID8000(SR.ID2136));

                return;
            }

            // Store the HttpResponseMessage in the transaction properties.
            context.Transaction.SetProperty(typeof(HttpResponseMessage).FullName!, response
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0175)));
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
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<DisposeHttpRequest<TContext>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            request.Dispose();

            // Remove the request from the transaction properties.
            context.Transaction.SetProperty<HttpRequestMessage>(typeof(HttpRequestMessage).FullName!, null);

            return ValueTask.CompletedTask;
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
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<DecompressResponseContent<TContext>>()
                .SetOrder(ExtractJsonHttpResponse<TContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // Note: automatic content decompression can be enabled by constructing an HttpClient wrapping
            // a generic HttpClientHandler, a SocketsHttpHandler or a WinHttpHandler instance with the
            // AutomaticDecompression property set to the desired algorithms (e.g GZip, Deflate or Brotli).
            //
            // Unfortunately, while convenient and efficient, relying on this property has a downside:
            // setting AutomaticDecompression always overrides the Accept-Encoding header of all requests
            // to include the selected algorithms without offering a way to make this behavior opt-in.
            // Sadly, using HTTP content compression with transport security enabled has security implications
            // that could potentially lead to compression side-channel attacks if the client is used with
            // remote endpoints that reflect user-defined data and contain secret values (e.g BREACH attacks).
            //
            // Since OpenIddict itself cannot safely assume such scenarios will never happen (e.g a token request
            // will typically be sent with an authorization code that can be defined by a malicious user and can
            // potentially be reflected in the token response depending on the configuration of the remote server),
            // it is safer to disable compression by default by not sending an Accept-Encoding header while
            // still allowing encoded responses to be processed (e.g StackExchange forces content compression
            // for all the supported HTTP APIs even if no Accept-Encoding header is explicitly sent by the client).
            //
            // For these reasons, OpenIddict doesn't rely on the automatic decompression feature and uses
            // a custom event handler to deal with GZip/Deflate/Brotli-encoded responses, so that servers
            // that require using HTTP compression can be supported without having to use it for all servers.

            // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var response = context.Transaction.GetHttpResponseMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            // If no Content-Encoding header was returned, keep the response stream as-is.
            if (response.Content is not { Headers.ContentEncoding.Count: > 0 })
            {
                return;
            }

            // On iOS, the generic HttpClientHandler type instantiates a NSUrlSessionHandler under the hood.
            // NSURLSession is known for enforcing response compression on certain versions of iOS: when
            // using this type, an Accept-Encoding header is automatically attached by iOS and the response
            // is automatically decompressed. Unfortunately, NSUrlSessionHandler doesn't remove the
            // Content-Encoding header from the response, which leads to incorrect results when trying
            // to decompress the content a second time. To avoid that, the entire logic used in this
            // handler is ignored on iOS if the native HTTP handler (NSUrlSessionHandler) is used.
            if (OperatingSystem.IsIOS() &&
                AppContext.TryGetSwitch("System.Net.Http.UseNativeHttpHandler", out bool value) && value)
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

                if (string.Equals(encoding, ContentEncodings.Gzip, StringComparison.OrdinalIgnoreCase))
                {
                    stream ??= await response.Content.ReadAsStreamAsync().WaitAsync(context.CancellationToken);
                    stream = new GZipStream(stream, CompressionMode.Decompress);
                }

#if NET
                // Note: some server implementations are known to incorrectly implement the "Deflate" compression
                // algorithm and don't wrap the compressed data in a ZLib frame as required by the specifications.
                //
                // Such implementations are deliberately not supported here. In this case, it is recommended to avoid
                // including "deflate" in the Accept-Encoding header if the server is known to be non-compliant.
                //
                // For more information, read https://www.rfc-editor.org/rfc/rfc9110.html#name-deflate-coding.
                else if (string.Equals(encoding, ContentEncodings.Deflate, StringComparison.OrdinalIgnoreCase))
                {
                    stream ??= await response.Content.ReadAsStreamAsync().WaitAsync(context.CancellationToken);
                    stream = new ZLibStream(stream, CompressionMode.Decompress);
                }

                else if (string.Equals(encoding, ContentEncodings.Brotli, StringComparison.OrdinalIgnoreCase))
                {
                    stream ??= await response.Content.ReadAsStreamAsync().WaitAsync(context.CancellationToken);
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
                await content.LoadIntoBufferAsync(context.CancellationToken);

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
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<ExtractJsonHttpResponse<TContext>>()
                .SetOrder(ExtractWwwAuthenticateHeader<TContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // Don't overwrite the response if one was already provided.
            if (context.Transaction.Response is not null)
            {
                return;
            }

            // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var response = context.Transaction.GetHttpResponseMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            // If the returned Content-Type doesn't indicate the response has a JSON payload,
            // ignore it and allow other handlers in the pipeline to process the HTTP response.
            if (!string.Equals(response.Content.Headers.ContentType?.MediaType,
                MediaTypes.Json, StringComparison.OrdinalIgnoreCase) &&
                !HasJsonStructuredSyntaxSuffix(response.Content.Headers.ContentType))
            {
                return;
            }

            try
            {
                // Note: ReadFromJsonAsync() automatically validates the content encoding and transparently
                // transcodes the response stream if a non-UTF-8 response is returned by the remote server.
                context.Transaction.Response = await response.Content.ReadFromJsonAsync(
                    OpenIddictSerializer.Default.Response, context.CancellationToken);
            }

            // If an exception is thrown at this stage, this likely means the returned response was not a valid
            // JSON response or was not correctly formatted as a JSON object. This typically happens when
            // a server error occurs while the JSON response is being generated and returned to the client.
            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                context.Logger.LogError(6183, exception, SR.GetResourceString(SR.ID6183),
                    await response.Content.ReadAsStringAsync(context.CancellationToken));

                context.Reject(
                    error: Errors.ServerError,
                    description: SR.GetResourceString(SR.ID2137),
                    uri: SR.FormatID8000(SR.ID2137));

                return;
            }

            static bool HasJsonStructuredSyntaxSuffix(MediaTypeHeaderValue? type) =>
                // If the length of the media type is less than the expected number of characters needed
                // to compose a JSON-derived type (i.e application/*+json), assume the content is not JSON.
                type?.MediaType is { Length: >= 18 } &&
                // JSON media types MUST always start with "application/".
                type.MediaType.AsSpan(0, 12).Equals("application/".AsSpan(), StringComparison.OrdinalIgnoreCase) &&
                // JSON media types MUST always end with "+json".
                type.MediaType.AsSpan()[^5..].Equals("+json".AsSpan(), StringComparison.OrdinalIgnoreCase);
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
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<ExtractWwwAuthenticateHeader<TContext>>()
                .SetOrder(ExtractEmptyHttpResponse<TContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // Don't overwrite the response if one was already provided.
            if (context.Transaction.Response is not null)
            {
                return ValueTask.CompletedTask;
            }

            // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var response = context.Transaction.GetHttpResponseMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            if (response.Headers.WwwAuthenticate.Count is 0)
            {
                return ValueTask.CompletedTask;
            }

            context.Transaction.Response = new OpenIddictResponse(response.Headers.WwwAuthenticate
                .Where(static header => !string.IsNullOrEmpty(header.Parameter))
                .SelectMany(static header => ParseParameters(header.Parameter!)));

            return ValueTask.CompletedTask;

            static IEnumerable<KeyValuePair<string, string?>> ParseParameters(string parameter)
            {
                var index = 0;

                while (index < parameter.Length)
                {
                    // Skip leading whitespaces and commas.
                    while (index < parameter.Length && (char.IsWhiteSpace(parameter[index]) || parameter[index] is ','))
                    {
                        index++;
                    }

                    // Parse the parameter key.
                    var start = index;
                    while (index < parameter.Length && parameter[index] is not ('=' or ','))
                    {
                        index++;
                    }

                    if (index >= parameter.Length || parameter[index] is ',')
                    {
                        break;
                    }

                    var key = parameter[start..index].Trim();

                    // Skip the equals sign.
                    index++;
                    while (index < parameter.Length && char.IsWhiteSpace(parameter[index]))
                    {
                        index++;
                    }

                    // Parse the parameter value.
                    string value;
                    if (index < parameter.Length && parameter[index] is '"')
                    {
                        // Skip the opening quote.
                        index++;

                        var builder = new StringBuilder();

                        while (index < parameter.Length)
                        {
                            if (parameter[index] is '\\' && index + 1 < parameter.Length)
                            {
                                builder.Append(parameter[index + 1]);
                                index += 2;
                            }

                            else if (parameter[index] is '"')
                            {
                                // Skip the closing quote.
                                index++;
                                break;
                            }

                            else
                            {
                                builder.Append(parameter[index++]);
                            }
                        }

                        value = builder.ToString();
                    }

                    else
                    {
                        start = index;
                        while (index < parameter.Length && parameter[index] is not ',' && !char.IsWhiteSpace(parameter[index]))
                        {
                            index++;
                        }

                        value = parameter[start..index].Trim();
                    }

                    yield return KeyValuePair.Create<string, string?>(key, value);
                }
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting empty responses from the HTTP response.
    /// </summary>
    public sealed class ExtractEmptyHttpResponse<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<ExtractEmptyHttpResponse<TContext>>()
                .SetOrder(ValidateHttpResponse<TContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // Don't overwrite the response if one was already provided.
            if (context.Transaction.Response is not null)
            {
                return ValueTask.CompletedTask;
            }

            // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var response = context.Transaction.GetHttpResponseMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            // Only process an empty response if no Content-Type header is attached to the
            // HTTP response and the Content-Length header is not present or set to 0.
            if (response.Content.Headers is { ContentLength: null or 0, ContentType: null })
            {
                context.Transaction.Response = new OpenIddictResponse();
            }

            return ValueTask.CompletedTask;
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
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<ValidateHttpResponse<TContext>>()
                .SetOrder(DisposeHttpResponse<TContext>.Descriptor.Order - 50_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var response = context.Transaction.GetHttpResponseMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            // At this stage, return a generic error based on the HTTP status code if no
            // error could be extracted from the payload or from the WWW-Authenticate header.
            if (!response.IsSuccessStatusCode && string.IsNullOrEmpty(context.Transaction.Response?.Error))
            {
                context.Logger.LogError(6184, SR.GetResourceString(SR.ID6184), response.StatusCode,
                    await response.Content.ReadAsStringAsync(context.CancellationToken));

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
                context.Logger.LogError(6185, SR.GetResourceString(SR.ID6185), response.StatusCode,
                    response.Content.Headers.ContentType, await response.Content.ReadAsStringAsync(context.CancellationToken));

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
                .AddFilter<RequireHttpUri>()
                .UseSingletonHandler<DisposeHttpResponse<TContext>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var response = context.Transaction.GetHttpResponseMessage()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            response.Dispose();

            // Remove the response from the transaction properties.
            context.Transaction.SetProperty<HttpResponseMessage>(typeof(HttpResponseMessage).FullName!, null);

            return ValueTask.CompletedTask;
        }
    }
}
