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
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Validation.SystemNetHttp;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictValidationSystemNetHttpHandlers
{
    public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; }
        = ImmutableArray.Create<OpenIddictValidationHandlerDescriptor>()
            .AddRange(Discovery.DefaultHandlers)
            .AddRange(Introspection.DefaultHandlers);

    /// <summary>
    /// Contains the logic responsible for preparing an HTTP GET request message.
    /// </summary>
    public class PrepareGetHttpRequest<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<PrepareGetHttpRequest<TContext>>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
    public class PreparePostHttpRequest<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<PreparePostHttpRequest<TContext>>()
                .SetOrder(PrepareGetHttpRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
    public class AttachQueryStringParameters<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<AttachQueryStringParameters<TContext>>()
                .SetOrder(AttachFormParameters<TContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
    public class AttachFormParameters<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<AttachFormParameters<TContext>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
    public class SendHttpRequest<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseExternalContext
    {
        private readonly IHttpClientFactory _factory;

        public SendHttpRequest(IHttpClientFactory factory)
            => _factory = factory ?? throw new ArgumentNullException(nameof(factory));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<SendHttpRequest<TContext>>()
                .SetOrder(DisposeHttpRequest<TContext>.Descriptor.Order - 50_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
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

            var assembly = typeof(OpenIddictValidationSystemNetHttpOptions).Assembly.GetName();
            using var client = _factory.CreateClient(assembly.Name!) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0174));

#if SUPPORTS_HTTP_CLIENT_DEFAULT_REQUEST_VERSION
            // If supported, import the HTTP version from the client instance.
            request.Version = client.DefaultRequestVersion;
#endif
            HttpResponseMessage response;

            try
            {
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
    public class DisposeHttpRequest<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<DisposeHttpRequest<TContext>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
    public class ExtractJsonHttpResponse<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<ExtractJsonHttpResponse<TContext>>()
                .SetOrder(DisposeHttpResponse<TContext>.Descriptor.Order - 50_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
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

            // The status code is deliberately not validated to ensure even errored responses
            // (typically in the 4xx range) can be deserialized and handled by the event handlers.

            try
            {
                try
                {
                    // Note: ReadFromJsonAsync() automatically validates the content encoding and transparently
                    // transcodes the response stream if a non-UTF-8 response is returned by the remote server.
                    context.Transaction.Response = await response.Content.ReadFromJsonAsync<OpenIddictResponse>();
                }

                // Initial versions of System.Net.Http.Json were known to eagerly validate the media type returned
                // as part of the HTTP Content-Type header and throw a NotSupportedException. If such an exception
                // is caught, try to extract the response using the less efficient string-based deserialization,
                // that will also take care of handling non-UTF-8 encodings but won't validate the media type.
                catch (NotSupportedException)
                {
                    context.Transaction.Response = JsonSerializer.Deserialize<OpenIddictResponse>(
                        await response.Content.ReadAsStringAsync());
                }
            }

            // If an exception is thrown at this stage, this likely means the returned response was not a valid
            // JSON response or was not correctly formatted as a JSON object. This typically happens when
            // a server error occurs and a default error page is returned by the remote HTTP server.
            // In this case, log the error details and return a generic error to stop processing the event.
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
    /// Contains the logic responsible for disposing of the HTTP response message.
    /// </summary>
    public class DisposeHttpResponse<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<DisposeHttpResponse<TContext>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
