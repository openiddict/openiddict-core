/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.WebUtilities;

namespace OpenIddict.Client.AspNetCore;

public static partial class OpenIddictClientAspNetCoreHandlers
{
    public static class Authentication
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authorization request processing:
             */
            ProcessQueryRequest.Descriptor,

            /*
             * Redirection request extraction:
             */
            ExtractGetOrPostRequest<ExtractRedirectionRequestContext>.Descriptor,

            /*
             * Redirection request handling:
             */
            EnablePassthroughMode<HandleRedirectionRequestContext, RequireRedirectionEndpointPassthroughEnabled>.Descriptor,

            /*
             * Redirection response handling:
             */
            AttachHttpResponseCode<ApplyRedirectionResponseContext>.Descriptor,
            AttachCacheControlHeader<ApplyRedirectionResponseContext>.Descriptor,
            ProcessPassthroughErrorResponse<ApplyRedirectionResponseContext, RequireRedirectionEndpointPassthroughEnabled>.Descriptor,
            ProcessStatusCodePagesErrorResponse<ApplyRedirectionResponseContext>.Descriptor,
            ProcessLocalErrorResponse<ApplyRedirectionResponseContext>.Descriptor);

        /// <summary>
        /// Contains the logic responsible for processing authorization requests using 302 redirects.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ProcessQueryRequest : IOpenIddictClientHandler<ApplyAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyAuthorizationRequestContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ProcessQueryRequest>()
                    .SetOrder(50_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

                // Note: while initially not allowed by the core OAuth 2.0 specification, multiple parameters
                // with the same name are used by derived drafts like the OAuth 2.0 token exchange specification.
                // For consistency, multiple parameters with the same name are also supported by this endpoint.

#if SUPPORTS_MULTIPLE_VALUES_IN_QUERYHELPERS
                var location = QueryHelpers.AddQueryString(context.AuthorizationEndpoint,
                    from parameter in context.Request.GetParameters()
                    let values = (string?[]?) parameter.Value
                    where values is not null
                    from value in values
                    where !string.IsNullOrEmpty(value)
                    select KeyValuePair.Create(parameter.Key, value));
#else
                var location = context.AuthorizationEndpoint;

                foreach (var (key, value) in
                    from parameter in context.Request.GetParameters()
                    let values = (string?[]?) parameter.Value
                    where values is not null
                    from value in values
                    where !string.IsNullOrEmpty(value)
                    select (parameter.Key, Value: value))
                {
                    location = QueryHelpers.AddQueryString(location, key, value);
                }
#endif
                response.Redirect(location);
                context.HandleRequest();

                return default;
            }
        }
    }
}
