/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using Microsoft.Extensions.Logging;
using Owin;

namespace OpenIddict.Server.Owin;

public static partial class OpenIddictServerOwinHandlers
{
    public static class Device
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Device request extraction:
             */
            ExtractPostRequest<ExtractDeviceRequestContext>.Descriptor,
            ExtractBasicAuthenticationCredentials<ExtractDeviceRequestContext>.Descriptor,

            /*
             * Device response processing:
             */
            AttachHttpResponseCode<ApplyDeviceResponseContext>.Descriptor,
            AttachCacheControlHeader<ApplyDeviceResponseContext>.Descriptor,
            AttachWwwAuthenticateHeader<ApplyDeviceResponseContext>.Descriptor,
            ProcessJsonResponse<ApplyDeviceResponseContext>.Descriptor,

            /*
             * Verification request extraction:
             */
            ExtractGetOrPostRequest<ExtractVerificationRequestContext>.Descriptor,

            /*
             * Verification request handling:
             */
            EnablePassthroughMode<HandleVerificationRequestContext, RequireVerificationEndpointPassthroughEnabled>.Descriptor,

            /*
             * Verification response processing:
             */
            AttachHttpResponseCode<ApplyVerificationResponseContext>.Descriptor,
            AttachCacheControlHeader<ApplyVerificationResponseContext>.Descriptor,
            ProcessHostRedirectionResponse.Descriptor,
            ProcessPassthroughErrorResponse<ApplyVerificationResponseContext, RequireVerificationEndpointPassthroughEnabled>.Descriptor,
            ProcessLocalErrorResponse<ApplyVerificationResponseContext>.Descriptor,
            ProcessEmptyResponse<ApplyVerificationResponseContext>.Descriptor);
    }

    /// <summary>
    /// Contains the logic responsible for processing verification responses that should trigger a host redirection.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class ProcessHostRedirectionResponse : IOpenIddictServerHandler<ApplyVerificationResponseContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyVerificationResponseContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ProcessHostRedirectionResponse>()
                .SetOrder(ProcessPassthroughErrorResponse<ApplyVerificationResponseContext, RequireVerificationEndpointPassthroughEnabled>.Descriptor.Order - 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ApplyVerificationResponseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Note: this handler only redirects the user agent to the address specified in
            // the properties when there's no error or if the error is an access_denied error.
            if (!string.IsNullOrEmpty(context.Response.Error) &&
                !string.Equals(context.Response.Error, Errors.AccessDenied, StringComparison.Ordinal))
            {
                return default;
            }

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (!string.IsNullOrEmpty(properties?.RedirectUri))
            {
                response.Redirect(properties.RedirectUri);

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6144));
                context.HandleRequest();
            }

            return default;
        }
    }
}
