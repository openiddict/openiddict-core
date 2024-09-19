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
    public static class Introspection
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Introspection request processing:
             */
            CreateHttpClient<PrepareIntrospectionRequestContext>.Descriptor,
            PreparePostHttpRequest<PrepareIntrospectionRequestContext>.Descriptor,
            AttachHttpVersion<PrepareIntrospectionRequestContext>.Descriptor,
            AttachJsonAcceptHeaders<PrepareIntrospectionRequestContext>.Descriptor,
            AttachUserAgentHeader<PrepareIntrospectionRequestContext>.Descriptor,
            AttachFromHeader<PrepareIntrospectionRequestContext>.Descriptor,
            AttachBasicAuthenticationCredentials<PrepareIntrospectionRequestContext>.Descriptor,
            AttachHttpParameters<PrepareIntrospectionRequestContext>.Descriptor,
            SendHttpRequest<ApplyIntrospectionRequestContext>.Descriptor,
            DisposeHttpRequest<ApplyIntrospectionRequestContext>.Descriptor,

            /*
             * Introspection response processing:
             */
            DecompressResponseContent<ExtractIntrospectionResponseContext>.Descriptor,
            ExtractJsonHttpResponse<ExtractIntrospectionResponseContext>.Descriptor,
            ExtractWwwAuthenticateHeader<ExtractIntrospectionResponseContext>.Descriptor,
            ValidateHttpResponse<ExtractIntrospectionResponseContext>.Descriptor,
            DisposeHttpResponse<ExtractIntrospectionResponseContext>.Descriptor
        ]);
    }
}
