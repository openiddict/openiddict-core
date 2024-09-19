/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace OpenIddict.Client.SystemNetHttp;

public static partial class OpenIddictClientSystemNetHttpHandlers
{
    public static class Exchange
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Token request processing:
             */
            CreateHttpClient<PrepareTokenRequestContext>.Descriptor,
            PreparePostHttpRequest<PrepareTokenRequestContext>.Descriptor,
            AttachHttpVersion<PrepareTokenRequestContext>.Descriptor,
            AttachJsonAcceptHeaders<PrepareTokenRequestContext>.Descriptor,
            AttachUserAgentHeader<PrepareTokenRequestContext>.Descriptor,
            AttachFromHeader<PrepareTokenRequestContext>.Descriptor,
            AttachBasicAuthenticationCredentials<PrepareTokenRequestContext>.Descriptor,
            AttachHttpParameters<PrepareTokenRequestContext>.Descriptor,
            SendHttpRequest<ApplyTokenRequestContext>.Descriptor,
            DisposeHttpRequest<ApplyTokenRequestContext>.Descriptor,

            /*
             * Token response processing:
             */
            DecompressResponseContent<ExtractTokenResponseContext>.Descriptor,
            ExtractJsonHttpResponse<ExtractTokenResponseContext>.Descriptor,
            ExtractWwwAuthenticateHeader<ExtractTokenResponseContext>.Descriptor,
            ValidateHttpResponse<ExtractTokenResponseContext>.Descriptor,
            DisposeHttpResponse<ExtractTokenResponseContext>.Descriptor
        ]);
    }
}
