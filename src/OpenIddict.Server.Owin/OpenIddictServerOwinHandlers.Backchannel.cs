/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Server.Owin;

public static partial class OpenIddictServerOwinHandlers
{
    public static class Backchannel
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Backchannel authentication request extraction:
             */
            ExtractPostRequest<ExtractBackchannelAuthenticationRequestContext>.Descriptor,
            ValidateClientAuthenticationMethod<ExtractBackchannelAuthenticationRequestContext>.Descriptor,
            ExtractClientCertificate<ExtractBackchannelAuthenticationRequestContext>.Descriptor,
            ExtractBasicAuthenticationCredentials<ExtractBackchannelAuthenticationRequestContext>.Descriptor,

            /*
             * Backchannel authentication request handling:
             */
            EnablePassthroughMode<HandleBackchannelAuthenticationRequestContext, RequireBackchannelAuthenticationEndpointPassthroughEnabled>.Descriptor,

            /*
             * Backchannel authentication response processing:
             */
            AttachHttpResponseCode<ApplyBackchannelAuthenticationResponseContext>.Descriptor,
            AttachOwinResponseChallenge<ApplyBackchannelAuthenticationResponseContext>.Descriptor,
            SuppressFormsAuthenticationRedirect<ApplyBackchannelAuthenticationResponseContext>.Descriptor,
            AttachCacheControlHeader<ApplyBackchannelAuthenticationResponseContext>.Descriptor,
            AttachWwwAuthenticateHeader<ApplyBackchannelAuthenticationResponseContext>.Descriptor,
            ProcessJsonResponse<ApplyBackchannelAuthenticationResponseContext>.Descriptor
        ];
    }
}
