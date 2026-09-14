/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpConstants;

namespace OpenIddict.Client.SystemNetHttp;

public static partial class OpenIddictClientSystemNetHttpHandlers
{
    public static class Registration
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Registration request processing:
             */
            CreateHttpClient<PrepareRegistrationRequestContext>.Descriptor,
            PrepareRegistrationHttpRequest.Descriptor,
            AttachHttpVersion<PrepareRegistrationRequestContext>.Descriptor,
            AttachJsonAcceptHeaders<PrepareRegistrationRequestContext>.Descriptor,
            AttachUserAgentHeader<PrepareRegistrationRequestContext>.Descriptor,
            AttachFromHeader<PrepareRegistrationRequestContext>.Descriptor,
            AttachBearerAccessToken.Descriptor,
            AttachJsonHttpParameters.Descriptor,
            SendHttpRequest<ApplyRegistrationRequestContext>.Descriptor,
            DisposeHttpRequest<ApplyRegistrationRequestContext>.Descriptor,

            /*
             * Registration response processing:
             */
            DecompressResponseContent<ExtractRegistrationResponseContext>.Descriptor,
            ExtractJsonHttpResponse<ExtractRegistrationResponseContext>.Descriptor,
            ExtractWwwAuthenticateHeader<ExtractRegistrationResponseContext>.Descriptor,
            ExtractEmptyHttpResponse<ExtractRegistrationResponseContext>.Descriptor,
            ValidateHttpResponse<ExtractRegistrationResponseContext>.Descriptor,
            DisposeHttpResponse<ExtractRegistrationResponseContext>.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for preparing an HTTP request message using the method attached to the context.
        /// </summary>
        public sealed class PrepareRegistrationHttpRequest : IOpenIddictClientHandler<PrepareRegistrationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareRegistrationRequestContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<PrepareRegistrationHttpRequest>()
                    .SetOrder(PreparePostHttpRequest<PrepareRegistrationRequestContext>.Descriptor.Order)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareRegistrationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Store the HttpRequestMessage in the transaction properties.
                context.Transaction.SetProperty(typeof(HttpRequestMessage).FullName!,
                    new HttpRequestMessage(new HttpMethod(context.RequestMethod), context.RemoteUri));

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the initial access token or
        /// the registration access token to the standard HTTP Authorization header.
        /// </summary>
        public sealed class AttachBearerAccessToken : IOpenIddictClientHandler<PrepareRegistrationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareRegistrationRequestContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<AttachBearerAccessToken>()
                    .SetOrder(AttachJsonHttpParameters.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareRegistrationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // Note: don't overwrite the authorization header if one was already set by another handler.
                if (request.Headers.Authorization is null && !string.IsNullOrEmpty(context.AccessToken))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue(Schemes.Bearer, context.AccessToken);
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the client metadata to the JSON payload
        /// of POST and PUT requests (RFC 7591, section 3.1 and RFC 7592, section 2.2).
        /// </summary>
        public sealed class AttachJsonHttpParameters : IOpenIddictClientHandler<PrepareRegistrationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareRegistrationRequestContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<AttachJsonHttpParameters>()
                    .SetOrder(AttachHttpParameters<PrepareRegistrationRequestContext>.Descriptor.Order)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareRegistrationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                if (request.Method != HttpMethod.Post && request.Method != HttpMethod.Put)
                {
                    return ValueTask.CompletedTask;
                }

                using var stream = new MemoryStream();
                using (var writer = new Utf8JsonWriter(stream))
                {
                    context.Transaction.Request.WriteTo(writer);
                }

                request.Content = new ByteArrayContent(stream.ToArray());
                request.Content.Headers.ContentType = new MediaTypeHeaderValue(MediaTypes.Json) { CharSet = "utf-8" };

                return ValueTask.CompletedTask;
            }
        }
    }
}
