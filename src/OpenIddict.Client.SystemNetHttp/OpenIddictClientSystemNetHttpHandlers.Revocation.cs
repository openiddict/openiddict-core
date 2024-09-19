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
    public static class Revocation
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Revocation request processing:
             */
            CreateHttpClient<PrepareRevocationRequestContext>.Descriptor,
            PreparePostHttpRequest<PrepareRevocationRequestContext>.Descriptor,
            AttachHttpVersion<PrepareRevocationRequestContext>.Descriptor,
            AttachJsonAcceptHeaders<PrepareRevocationRequestContext>.Descriptor,
            AttachUserAgentHeader<PrepareRevocationRequestContext>.Descriptor,
            AttachFromHeader<PrepareRevocationRequestContext>.Descriptor,
            AttachBasicAuthenticationCredentials<PrepareRevocationRequestContext>.Descriptor,
            AttachHttpParameters<PrepareRevocationRequestContext>.Descriptor,
            SendHttpRequest<ApplyRevocationRequestContext>.Descriptor,
            DisposeHttpRequest<ApplyRevocationRequestContext>.Descriptor,

            /*
             * Revocation response processing:
             */
            DecompressResponseContent<ExtractRevocationResponseContext>.Descriptor,
            ExtractJsonHttpResponse<ExtractRevocationResponseContext>.Descriptor,
            ExtractWwwAuthenticateHeader<ExtractRevocationResponseContext>.Descriptor,
            ExtractEmptyHttpResponse<ExtractRevocationResponseContext>.Descriptor,
            ValidateHttpResponse<ExtractRevocationResponseContext>.Descriptor,
            DisposeHttpResponse<ExtractRevocationResponseContext>.Descriptor
        ]);
    }
}
