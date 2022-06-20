/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Server.Owin;

public static partial class OpenIddictServerOwinHandlers
{
    public static class Userinfo
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Userinfo request extraction:
             */
            ExtractGetOrPostRequest<ExtractUserinfoRequestContext>.Descriptor,
            ExtractAccessToken<ExtractUserinfoRequestContext>.Descriptor,

            /*
             * Userinfo request handling:
             */
            EnablePassthroughMode<HandleUserinfoRequestContext, RequireUserinfoEndpointPassthroughEnabled>.Descriptor,

            /*
             * Userinfo response processing:
             */
            AttachHttpResponseCode<ApplyUserinfoResponseContext>.Descriptor,
            AttachOwinResponseChallenge<ApplyUserinfoResponseContext>.Descriptor,
            SuppressFormsAuthenticationRedirect<ApplyUserinfoResponseContext>.Descriptor,
            AttachWwwAuthenticateHeader<ApplyUserinfoResponseContext>.Descriptor,
            ProcessChallengeErrorResponse<ApplyUserinfoResponseContext>.Descriptor,
            ProcessJsonResponse<ApplyUserinfoResponseContext>.Descriptor);
    }
}
