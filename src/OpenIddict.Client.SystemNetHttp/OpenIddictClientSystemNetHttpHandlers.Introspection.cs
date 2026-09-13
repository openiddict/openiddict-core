/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Net.Http;
using System.Net.Http.Headers;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpConstants;

namespace OpenIddict.Client.SystemNetHttp;

public static partial class OpenIddictClientSystemNetHttpHandlers
{
    public static class Introspection
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Introspection request processing:
             */
            CreateHttpClient<PrepareIntrospectionRequestContext>.Descriptor,
            PreparePostHttpRequest<PrepareIntrospectionRequestContext>.Descriptor,
            AttachHttpVersion<PrepareIntrospectionRequestContext>.Descriptor,
            AttachJsonAcceptHeaders<PrepareIntrospectionRequestContext>.Descriptor,
            AttachIntrospectionResponseAcceptHeader.Descriptor,
            AttachUserAgentHeader<PrepareIntrospectionRequestContext>.Descriptor,
            AttachFromHeader<PrepareIntrospectionRequestContext>.Descriptor,
            AttachBasicAuthenticationCredentials<PrepareIntrospectionRequestContext>.Descriptor,
            AttachHttpParameters<PrepareIntrospectionRequestContext>.Descriptor,
            SendHttpRequest<ApplyIntrospectionRequestContext>.Descriptor,
            DisposeHttpRequest<ApplyIntrospectionRequestContext>.Descriptor,

            /*
             * Introspection response processing:
             */
            DecompressResponseContent<ExtractIntrospectionResponseContext>.Descriptor,
            ExtractIntrospectionTokenHttpResponse.Descriptor,
            ExtractJsonHttpResponse<ExtractIntrospectionResponseContext>.Descriptor,
            ExtractWwwAuthenticateHeader<ExtractIntrospectionResponseContext>.Descriptor,
            ValidateHttpResponse<ExtractIntrospectionResponseContext>.Descriptor,
            DisposeHttpResponse<ExtractIntrospectionResponseContext>.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for requesting a JSON Web Token introspection response, if applicable.
        /// </summary>
        public sealed class AttachIntrospectionResponseAcceptHeader : IOpenIddictClientHandler<PrepareIntrospectionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareIntrospectionRequestContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<AttachIntrospectionResponseAcceptHeader>()
                    .SetOrder(AttachJsonAcceptHeaders<PrepareIntrospectionRequestContext>.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareIntrospectionRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!context.Registration.RequireJsonWebTokenIntrospectionResponses)
                {
                    return ValueTask.CompletedTask;
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // Replace the JSON media type by the JSON Web Token introspection response media type.
                //
                // See https://datatracker.ietf.org/doc/html/rfc9701#section-4 for more information.
                request.Headers.Accept.Clear();
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(MediaTypes.IntrospectionResponseJsonWebToken));

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the JSON Web Token from the introspection response, if applicable.
        /// </summary>
        public sealed class ExtractIntrospectionTokenHttpResponse : IOpenIddictClientHandler<ExtractIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ExtractIntrospectionResponseContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<ExtractIntrospectionTokenHttpResponse>()
                    .SetOrder(ExtractJsonHttpResponse<ExtractIntrospectionResponseContext>.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ExtractIntrospectionResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Don't overwrite the response if one was already provided.
                if (context.Response is not null || !string.IsNullOrEmpty(context.IntrospectionResponseToken))
                {
                    return;
                }

                // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var response = context.Transaction.GetHttpResponseMessage()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // Note: introspection responses can be returned as JSON objects or as JSON Web Tokens (RFC 9701).
                // Only the latter are extracted by this handler, JSON responses are handled by ExtractJsonHttpResponse.
                if (string.Equals(response.Content.Headers.ContentType?.MediaType,
                    MediaTypes.IntrospectionResponseJsonWebToken, StringComparison.OrdinalIgnoreCase))
                {
                    context.Response = new OpenIddictResponse();
                    context.IntrospectionResponseToken = await response.Content.ReadAsStringAsync(context.CancellationToken);
                }
            }
        }
    }
}
