/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Threading.Tasks;
using JetBrains.Annotations;
using OpenIddict.Abstractions;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.SystemNetHttp.OpenIddictValidationSystemNetHttpHandlerFilters;

namespace OpenIddict.Validation.SystemNetHttp
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictValidationSystemNetHttpHandlers
    {
        public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; }
            = ImmutableArray.Create<OpenIddictValidationHandlerDescriptor>()
                .AddRange(Discovery.DefaultHandlers)
                .AddRange(Introspection.DefaultHandlers);

        /// <summary>
        /// Contains the logic responsible of preparing an HTTP GET request message.
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
                    .Build();

            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var request = new HttpRequestMessage(HttpMethod.Get, context.Address);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Headers.AcceptCharset.Add(new StringWithQualityHeaderValue("utf-8"));

                // Store the HttpRequestMessage in the transaction properties.
                context.Transaction.Properties[typeof(HttpRequestMessage).FullName] = request;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of preparing an HTTP POST request message.
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
                    .Build();

            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var request = new HttpRequestMessage(HttpMethod.Post, context.Address);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Headers.AcceptCharset.Add(new StringWithQualityHeaderValue("utf-8"));

                // Store the HttpRequestMessage in the transaction properties.
                context.Transaction.Properties[typeof(HttpRequestMessage).FullName] = request;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching the query string parameters to the HTTP request.
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
                    .SetOrder(AttachFormParameters<TContext>.Descriptor.Order - 100_000)
                    .Build();

            public async ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage();
                if (request == null)
                {
                    throw new InvalidOperationException("The System.Net.Http request cannot be resolved.");
                }

                // Note: System.Net.Http doesn't expose convenient methods allowing to create
                // query strings from existing key/value pairs. To work around this limitation,
                // a FormUrlEncodedContent is instantiated and used to manually create the URL.
                using var content = new FormUrlEncodedContent(
                    from parameter in context.Request.GetParameters()
                    let values = (string[]) parameter.Value
                    where values != null
                    from value in values
                    select new KeyValuePair<string, string>(parameter.Key, value));

                var builder = new UriBuilder(request.RequestUri)
                {
                    Query = await content.ReadAsStringAsync()
                };

                request.RequestUri = builder.Uri;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching the form parameters to the HTTP request.
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
                    .Build();

            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage();
                if (request == null)
                {
                    throw new InvalidOperationException("The System.Net.Http request cannot be resolved.");
                }

                request.Content = new FormUrlEncodedContent(
                    from parameter in context.Request.GetParameters()
                    let values = (string[]) parameter.Value
                    where values != null
                    from value in values
                    select new KeyValuePair<string, string>(parameter.Key, value));

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of sending the HTTP request to the remote server.
        /// </summary>
        public class SendHttpRequest<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseExternalContext
        {
            private readonly IHttpClientFactory _factory;

            public SendHttpRequest([NotNull] IHttpClientFactory factory)
                => _factory = factory;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpMetadataAddress>()
                    .UseSingletonHandler<SendHttpRequest<TContext>>()
                    .SetOrder(int.MaxValue - 100_000)
                    .Build();

            public async ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage();
                if (request == null)
                {
                    throw new InvalidOperationException("The System.Net.Http request cannot be resolved.");
                }

                var assembly = typeof(OpenIddictValidationSystemNetHttpOptions).Assembly.GetName();
                using var client = _factory.CreateClient(assembly.Name);
                if (client == null)
                {
                    throw new InvalidOperationException("An unknown error occurred while creating a System.Net.Http client.");
                }

                var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead);
                if (response == null)
                {
                    throw new InvalidOperationException("An unknown error occurred while sending a System.Net.Http request.");
                }

                // Store the HttpResponseMessage in the transaction properties.
                context.Transaction.Properties[typeof(HttpResponseMessage).FullName] = response;
            }
        }

        /// <summary>
        /// Contains the logic responsible of extracting the response from the JSON-encoded HTTP body.
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
                    .SetOrder(int.MaxValue - 100_000)
                    .Build();

            public async ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var response = context.Transaction.GetHttpResponseMessage();
                if (response == null)
                {
                    throw new InvalidOperationException("The System.Net.Http request cannot be resolved.");
                }

                // The status code is deliberately not validated to ensure even errored responses
                // (typically in the 4xx range) can be deserialized and handled by the event handlers.

                // Note: ReadFromJsonAsync() automatically validates the content type and the content encoding
                // and transcode the response stream if a non-UTF-8 response is returned by the remote server.
                context.Response = await response.Content.ReadFromJsonAsync<OpenIddictResponse>();
            }
        }
    }
}
