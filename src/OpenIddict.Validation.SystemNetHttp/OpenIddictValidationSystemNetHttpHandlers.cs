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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using static OpenIddict.Validation.SystemNetHttp.OpenIddictValidationSystemNetHttpConstants;

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

            if (request.RequestUri is null || context.Transaction.Request.Count is 0)
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

#if SUPPORTS_HTTP_CLIENT_DEFAULT_REQUEST_VERSION_POLICY
            // If supported, import the HTTP version policy from the client instance.
            request.VersionPolicy = client.DefaultVersionPolicy;
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
                .SetOrder(ExtractWwwAuthenticateHeader<TContext>.Descriptor.Order - 1_000)
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
    public class ExtractWwwAuthenticateHeader<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<ExtractWwwAuthenticateHeader<TContext>>()
                .SetOrder(ValidateHttpResponse<TContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
    public class ValidateHttpResponse<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<ValidateHttpResponse<TContext>>()
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
                    description: SR.GetResourceString(SR.ID0328),
                    uri: SR.FormatID8000(SR.ID0328));

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
                    description: SR.GetResourceString(SR.ID0329),
                    uri: SR.FormatID8000(SR.ID0329));

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
