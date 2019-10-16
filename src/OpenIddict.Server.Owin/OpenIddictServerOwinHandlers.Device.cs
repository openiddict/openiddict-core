/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using static OpenIddict.Server.Owin.OpenIddictServerOwinHandlerFilters;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Owin
{
    public static partial class OpenIddictServerOwinHandlers
    {
        public static class Device
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Device request extraction:
                 */
                ExtractGetOrPostRequest<ExtractDeviceRequestContext>.Descriptor,

                /*
                 * Device response processing:
                 */
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
                ProcessHostRedirectionResponse<ApplyVerificationResponseContext>.Descriptor,
                ProcessPassthroughErrorResponse<ApplyVerificationResponseContext, RequireVerificationEndpointPassthroughEnabled>.Descriptor,
                ProcessLocalErrorResponse<ApplyVerificationResponseContext>.Descriptor,
                ProcessEmptyResponse<ApplyVerificationResponseContext>.Descriptor);
        }
    }
}
