/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreHandlerFilters;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.AspNetCore
{
    public static partial class OpenIddictServerAspNetCoreHandlers
    {
        public static class Userinfo
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Userinfo request extraction:
                 */
                ExtractGetRequest<ExtractUserinfoRequestContext>.Descriptor,
                ExtractAccessToken<ExtractUserinfoRequestContext>.Descriptor,

                /*
                 * Userinfo request handling:
                 */
                EnablePassthroughMode<HandleUserinfoRequestContext, RequireUserinfoEndpointPassthroughEnabled>.Descriptor,

                /*
                 * Userinfo response processing:
                 */
                ProcessJsonResponse<ApplyUserinfoResponseContext>.Descriptor);
        }
    }
}
