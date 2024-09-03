/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Server.Owin;

public static partial class OpenIddictServerOwinHandlers
{
    public static class UserInfo
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * UserInfo request extraction:
             */
            ExtractGetOrPostRequest<ExtractUserInfoRequestContext>.Descriptor,
            ExtractAccessToken<ExtractUserInfoRequestContext>.Descriptor,

            /*
             * UserInfo request handling:
             */
            EnablePassthroughMode<HandleUserInfoRequestContext, RequireUserInfoEndpointPassthroughEnabled>.Descriptor,

            /*
             * UserInfo response processing:
             */
            AttachHttpResponseCode<ApplyUserInfoResponseContext>.Descriptor,
            AttachOwinResponseChallenge<ApplyUserInfoResponseContext>.Descriptor,
            SuppressFormsAuthenticationRedirect<ApplyUserInfoResponseContext>.Descriptor,
            AttachWwwAuthenticateHeader<ApplyUserInfoResponseContext>.Descriptor,
            ProcessChallengeErrorResponse<ApplyUserInfoResponseContext>.Descriptor,
            ProcessJsonResponse<ApplyUserInfoResponseContext>.Descriptor
        ]);
    }
}
