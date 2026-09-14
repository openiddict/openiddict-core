/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Owin;
using static OpenIddict.Server.Owin.OpenIddictServerOwinConstants;

namespace OpenIddict.Server.Owin;

public static partial class OpenIddictServerOwinHandlers
{
    public static class Registration
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Registration request extraction:
             */
            ExtractRegistrationRequest.Descriptor,
            ExtractAccessToken<ExtractRegistrationRequestContext>.Descriptor,

            /*
             * Registration request handling:
             */
            EnablePassthroughMode<HandleRegistrationRequestContext, RequireRegistrationEndpointPassthroughEnabled>.Descriptor,

            /*
             * Registration response processing:
             */
            AttachHttpResponseCode<ApplyRegistrationResponseContext>.Descriptor,
            AttachOwinResponseChallenge<ApplyRegistrationResponseContext>.Descriptor,
            SuppressFormsAuthenticationRedirect<ApplyRegistrationResponseContext>.Descriptor,
            AttachCacheControlHeader<ApplyRegistrationResponseContext>.Descriptor,
            AttachWwwAuthenticateHeader<ApplyRegistrationResponseContext>.Descriptor,
            ProcessChallengeErrorResponse<ApplyRegistrationResponseContext>.Descriptor,
            ProcessNoContentResponse.Descriptor,
            ProcessJsonResponse<ApplyRegistrationResponseContext>.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for extracting registration requests: client metadata are extracted from
        /// the JSON payload of POST and PUT requests (RFC 7591, section 3.1 and RFC 7592, section 2.2) and the
        /// client identifier used by the client configuration endpoint is extracted from the query string.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public sealed class ExtractRegistrationRequest : IOpenIddictServerHandler<ExtractRegistrationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractRegistrationRequestContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ExtractRegistrationRequest>()
                    .SetOrder(ExtractPostRequest<ExtractRegistrationRequestContext>.Descriptor.Order)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ExtractRegistrationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

                var query = new OpenIddictRequest(
                    from parameter in request.Query
                    let values = new StringValues(parameter.Value)
                    select KeyValuePair.Create(parameter.Key, values));

                if (string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(request.Method, "DELETE", StringComparison.OrdinalIgnoreCase))
                {
                    context.Transaction.Request = query;
                    return;
                }

                if (!string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(request.Method, "PUT", StringComparison.OrdinalIgnoreCase))
                {
                    context.Logger.LogInformation(6137, SR.GetResourceString(SR.ID6137), request.Method);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2084),
                        uri: SR.FormatID8000(SR.ID2084));

                    return;
                }

                if (string.IsNullOrEmpty(request.ContentType))
                {
                    context.Logger.LogInformation(6138, SR.GetResourceString(SR.ID6138), Headers.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2081(Headers.ContentType),
                        uri: SR.FormatID8000(SR.ID2081));

                    return;
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!request.ContentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
                {
                    context.Logger.LogInformation(6139, SR.GetResourceString(SR.ID6139), Headers.ContentType, request.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2082(Headers.ContentType),
                        uri: SR.FormatID8000(SR.ID2082));

                    return;
                }

                JsonElement payload;

                try
                {
                    using var document = await JsonDocument.ParseAsync(request.Body, cancellationToken: context.CancellationToken);
                    payload = document.RootElement.Clone();
                }

                catch (JsonException)
                {
                    payload = default;
                }

                if (payload.ValueKind is not JsonValueKind.Object)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2419),
                        uri: SR.FormatID8000(SR.ID2419));

                    return;
                }

                var result = new OpenIddictRequest(payload);

                foreach (var parameter in query.GetParameters())
                {
                    if (!result.HasParameter(parameter.Key))
                    {
                        result.SetParameter(parameter.Key, parameter.Value);
                        continue;
                    }

                    // The client identifier specified in the payload of update requests MUST match
                    // the client identifier used to identify the client configuration endpoint.
                    //
                    // See https://datatracker.ietf.org/doc/html/rfc7592#section-2.2 for more information.
                    if (parameter.Key is Parameters.ClientId &&
                        !string.Equals((string?) result[Parameters.ClientId], (string?) parameter.Value, StringComparison.Ordinal))
                    {
                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2413(Parameters.ClientId),
                            uri: SR.FormatID8000(SR.ID2413));

                        return;
                    }
                }

                context.Transaction.Request = result;
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing successful client deletion responses, that MUST
        /// be returned as empty 204 responses (RFC 7592, section 2.3).
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public sealed class ProcessNoContentResponse : IOpenIddictServerHandler<ApplyRegistrationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyRegistrationResponseContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessNoContentResponse>()
                    .SetOrder(ProcessJsonResponse<ApplyRegistrationResponseContext>.Descriptor.Order - 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyRegistrationResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

                var response = context.Transaction.GetOwinRequest()?.Context.Response
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

                if (response.StatusCode is not 204)
                {
                    return ValueTask.CompletedTask;
                }

                context.Logger.LogInformation(6609, SR.GetResourceString(SR.ID6609));
                context.HandleRequest();

                return ValueTask.CompletedTask;
            }
        }
    }
}
