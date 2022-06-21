/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Net.Http.Headers;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpConstants;

namespace OpenIddict.Client.SystemNetHttp;

public static partial class OpenIddictClientSystemNetHttpHandlers
{
    public static class Userinfo
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Userinfo request processing:
             */
            PrepareGetHttpRequest<PrepareUserinfoRequestContext>.Descriptor,
            AttachUserAgent<PrepareUserinfoRequestContext>.Descriptor,
            AttachBearerAccessToken.Descriptor,
            AttachQueryStringParameters<PrepareUserinfoRequestContext>.Descriptor,
            SendHttpRequest<ApplyUserinfoRequestContext>.Descriptor,
            DisposeHttpRequest<ApplyUserinfoRequestContext>.Descriptor,

            /*
             * Userinfo response processing:
             */
            ExtractUserinfoTokenHttpResponse.Descriptor,
            ExtractJsonHttpResponse<ExtractUserinfoResponseContext>.Descriptor,
            ExtractWwwAuthenticateHeader<ExtractUserinfoResponseContext>.Descriptor,
            ValidateHttpResponse<ExtractUserinfoResponseContext>.Descriptor,
            DisposeHttpResponse<ExtractUserinfoResponseContext>.Descriptor);

        /// <summary>
        /// Contains the logic responsible for attaching the access token to the HTTP Authorization header.
        /// </summary>
        public class AttachBearerAccessToken : IOpenIddictClientHandler<PrepareUserinfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareUserinfoRequestContext>()
                    .AddFilter<RequireHttpMetadataAddress>()
                    .UseSingletonHandler<AttachBearerAccessToken>()
                    .SetOrder(AttachQueryStringParameters<PrepareUserinfoRequestContext>.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareUserinfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Request is not null, SR.GetResourceString(SR.ID4008));

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // Attach the authorization header containing the access token to the HTTP request.
                request.Headers.Authorization = new AuthenticationHeaderValue(Schemes.Bearer, context.Request.AccessToken);

                // Remove the access from the request payload to ensure it's not sent twice.
                context.Request.AccessToken = null;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the response from the userinfo response.
        /// </summary>
        public class ExtractUserinfoTokenHttpResponse : IOpenIddictClientHandler<ExtractUserinfoResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ExtractUserinfoResponseContext>()
                    .AddFilter<RequireHttpMetadataAddress>()
                    .UseSingletonHandler<ExtractUserinfoTokenHttpResponse>()
                    .SetOrder(ExtractJsonHttpResponse<ExtractUserinfoResponseContext>.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ExtractUserinfoResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Don't overwrite the response if one was already provided.
                if (context.Response is not null || !string.IsNullOrEmpty(context.UserinfoToken))
                {
                    return;
                }

                // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var response = context.Transaction.GetHttpResponseMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // The status code is deliberately not validated to ensure even errored responses
                // (typically in the 4xx range) can be deserialized and handled by the event handlers.

                // Note: userinfo responses can be of two types:
                //  - application/json responses containing a JSON object listing the user claims as-is.
                //  - application/jwt responses containing a signed/encrypted JSON Web Token containing the user claims.
                //
                // To support both types, this handler will try to extract the userinfo token as-is if the media type
                // is application/jwt and will rely on other handlers in the pipeline to process regular JSON responses.

                if (string.Equals(response.Content.Headers.ContentType?.MediaType,
                    MediaTypes.JsonWebToken, StringComparison.OrdinalIgnoreCase))
                {
                    context.Response = new OpenIddictResponse();
                    context.UserinfoToken = await response.Content.ReadAsStringAsync();

                    return;
                }
            }
        }
    }
}
