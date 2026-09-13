/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Client.SystemNetHttp;

public static partial class OpenIddictClientSystemNetHttpHandlers
{
    public static class Backchannel
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Backchannel authentication request processing:
             */
            CreateHttpClient<PrepareBackchannelAuthenticationRequestContext>.Descriptor,
            PreparePostHttpRequest<PrepareBackchannelAuthenticationRequestContext>.Descriptor,
            AttachHttpVersion<PrepareBackchannelAuthenticationRequestContext>.Descriptor,
            AttachJsonAcceptHeaders<PrepareBackchannelAuthenticationRequestContext>.Descriptor,
            AttachUserAgentHeader<PrepareBackchannelAuthenticationRequestContext>.Descriptor,
            AttachFromHeader<PrepareBackchannelAuthenticationRequestContext>.Descriptor,
            AttachBasicAuthenticationCredentials<PrepareBackchannelAuthenticationRequestContext>.Descriptor,
            AttachHttpParameters<PrepareBackchannelAuthenticationRequestContext>.Descriptor,
            SendHttpRequest<ApplyBackchannelAuthenticationRequestContext>.Descriptor,
            DisposeHttpRequest<ApplyBackchannelAuthenticationRequestContext>.Descriptor,

            /*
             * Backchannel authentication response processing:
             */
            DecompressResponseContent<ExtractBackchannelAuthenticationResponseContext>.Descriptor,
            ExtractJsonHttpResponse<ExtractBackchannelAuthenticationResponseContext>.Descriptor,
            ExtractWwwAuthenticateHeader<ExtractBackchannelAuthenticationResponseContext>.Descriptor,
            ValidateHttpResponse<ExtractBackchannelAuthenticationResponseContext>.Descriptor,
            DisposeHttpResponse<ExtractBackchannelAuthenticationResponseContext>.Descriptor
        ];
    }
}
