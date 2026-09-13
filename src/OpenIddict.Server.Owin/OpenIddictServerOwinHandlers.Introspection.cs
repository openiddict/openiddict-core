/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text;
using Microsoft.Extensions.Logging;
using Owin;
using static OpenIddict.Server.Owin.OpenIddictServerOwinConstants;

namespace OpenIddict.Server.Owin;

public static partial class OpenIddictServerOwinHandlers
{
    public static class Introspection
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Introspection request extraction:
             */
            ExtractGetOrPostRequest<ExtractIntrospectionRequestContext>.Descriptor,
            ValidateClientAuthenticationMethod<ExtractIntrospectionRequestContext>.Descriptor,
            ExtractClientCertificate<ExtractIntrospectionRequestContext>.Descriptor,
            ExtractBasicAuthenticationCredentials<ExtractIntrospectionRequestContext>.Descriptor,
            ExtractIntrospectionResponseMediaType.Descriptor,

            /*
             * Introspection response processing:
             */
            AttachHttpResponseCode<ApplyIntrospectionResponseContext>.Descriptor,
            AttachOwinResponseChallenge<ApplyIntrospectionResponseContext>.Descriptor,
            SuppressFormsAuthenticationRedirect<ApplyIntrospectionResponseContext>.Descriptor,
            AttachWwwAuthenticateHeader<ApplyIntrospectionResponseContext>.Descriptor,
            ProcessIntrospectionResponseToken.Descriptor,
            ProcessJsonResponse<ApplyIntrospectionResponseContext>.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for determining whether a JSON Web Token introspection response was requested.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public sealed class ExtractIntrospectionResponseMediaType : IOpenIddictServerHandler<ExtractIntrospectionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractIntrospectionRequestContext>()
                    .AddFilter<RequireOwinRequest>()
                    .AddFilter<RequireJsonWebTokenIntrospectionResponsesEnabled>()
                    .UseSingletonHandler<ExtractIntrospectionResponseMediaType>()
                    .SetOrder(ExtractBasicAuthenticationCredentials<ExtractIntrospectionRequestContext>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractIntrospectionRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

                // Note: a JSON Web Token response is only returned if the caller explicitly requested it.
                //
                // See https://datatracker.ietf.org/doc/html/rfc9701#section-4 for more information.
                context.Transaction.IsJsonWebTokenIntrospectionResponseRequested = OpenIddictHelpers.IncludesMediaType(
                    request.Headers.GetValues(Headers.Accept) ?? [],
                    JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.IntrospectionResponse);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for returning the JSON Web Token introspection response, if applicable.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public sealed class ProcessIntrospectionResponseToken : IOpenIddictServerHandler<ApplyIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyIntrospectionResponseContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessIntrospectionResponseToken>()
                    .SetOrder(ProcessJsonResponse<ApplyIntrospectionResponseContext>.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ApplyIntrospectionResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (string.IsNullOrEmpty(context.IntrospectionResponseToken))
                {
                    return;
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetOwinRequest()?.Context.Response
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

                context.Logger.LogInformation(6142, SR.GetResourceString(SR.ID6142), context.Transaction.Response);

                var payload = Encoding.UTF8.GetBytes(context.IntrospectionResponseToken);

                response.ContentLength = payload.Length;
                response.ContentType = JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.IntrospectionResponse;

                await response.Body.WriteAsync(payload, 0, payload.Length, context.CancellationToken);

                context.HandleRequest();
            }
        }
    }
}
