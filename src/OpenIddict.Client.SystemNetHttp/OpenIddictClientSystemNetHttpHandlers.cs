/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Text;

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
    public class PrepareGetHttpRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
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
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The HTTP request message is disposed later by a dedicated handler.")]
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var request = new HttpRequestMessage(HttpMethod.Get, context.Address)
            {
                Headers =
                {
                    Accept = { new MediaTypeWithQualityHeaderValue("application/json") },
                    AcceptCharset = { new StringWithQualityHeaderValue("utf-8") }
                }
            };

            // Store the HttpRequestMessage in the transaction properties.
            context.Transaction.SetProperty(typeof(HttpRequestMessage).FullName!, request);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing an HTTP POST request message.
    /// </summary>
    public class PreparePostHttpRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
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
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The HTTP request message is disposed later by a dedicated handler.")]
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var request = new HttpRequestMessage(HttpMethod.Post, context.Address)
            {
                Headers =
                {
                    Accept = { new MediaTypeWithQualityHeaderValue("application/json") },
                    AcceptCharset = { new StringWithQualityHeaderValue("utf-8") }
                }
            };

            // Store the HttpRequestMessage in the transaction properties.
            context.Transaction.SetProperty(typeof(HttpRequestMessage).FullName!, request);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the query string parameters to the HTTP request.
    /// </summary>
    public class AttachQueryStringParameters<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
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

            if (request.RequestUri is null || context.Transaction.Request.Count == 0)
            {
                return default;
            }

            var builder = new StringBuilder();

            foreach (var (key, value) in
                from parameter in context.Transaction.Request.GetParameters()
                let values = (string?[]?) parameter.Value
                where values is not null
                from value in values
                where !string.IsNullOrEmpty(value)
                select (parameter.Key, Value: value))
            {
                if (builder.Length > 0)
                {
                    builder.Append('&');
                }

                builder.Append(Uri.EscapeDataString(key));
                builder.Append('=');
                builder.Append(Uri.EscapeDataString(value));
            }

            // Compute the final request URI using the base address and the query string.
            request.RequestUri = new UriBuilder(request.RequestUri) { Query = builder.ToString() }.Uri;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the form parameters to the HTTP request.
    /// </summary>
    public class AttachFormParameters<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
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
                let values = (string[]?) parameter.Value
                where values is not null
                from value in values
                where !string.IsNullOrEmpty(value)
                select new KeyValuePair<string, string>(parameter.Key, value));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for sending the HTTP request to the remote server.
    /// </summary>
    public class SendHttpRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
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
                .SetOrder(DisposeHttpRequest<TContext>.Descriptor.Order - 50_000)
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
            var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0175));

            // Store the HttpResponseMessage in the transaction properties.
            context.Transaction.SetProperty(typeof(HttpResponseMessage).FullName!, response);
        }
    }

    /// <summary>
    /// Contains the logic responsible for disposing of the HTTP request message.
    /// </summary>
    public class DisposeHttpRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
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
    /// Contains the logic responsible for extracting the response from the JSON-encoded HTTP body.
    /// </summary>
    public class ExtractJsonHttpResponse<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<ExtractJsonHttpResponse<TContext>>()
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

            // The status code is deliberately not validated to ensure even errored responses
            // (typically in the 4xx range) can be deserialized and handled by the event handlers.

            // Note: ReadFromJsonAsync() automatically validates the content type and the content encoding
            // and transcode the response stream if a non-UTF-8 response is returned by the remote server.
            context.Transaction.Response = await response.Content.ReadFromJsonAsync<OpenIddictResponse>();
        }
    }

    /// <summary>
    /// Contains the logic responsible for disposing of the HTTP response message.
    /// </summary>
    public class DisposeHttpResponse<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseExternalContext
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
