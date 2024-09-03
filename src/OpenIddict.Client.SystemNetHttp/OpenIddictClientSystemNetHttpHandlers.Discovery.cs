/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Client.SystemNetHttp;

public static partial class OpenIddictClientSystemNetHttpHandlers
{
    public static class Discovery
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Configuration request processing:
             */
            CreateHttpClient<PrepareConfigurationRequestContext>.Descriptor,
            PrepareGetHttpRequest<PrepareConfigurationRequestContext>.Descriptor,
            AttachHttpVersion<PrepareConfigurationRequestContext>.Descriptor,
            AttachJsonAcceptHeaders<PrepareConfigurationRequestContext>.Descriptor,
            AttachUserAgentHeader<PrepareConfigurationRequestContext>.Descriptor,
            AttachFromHeader<PrepareConfigurationRequestContext>.Descriptor,
            AttachHttpParameters<PrepareConfigurationRequestContext>.Descriptor,
            SendHttpRequest<ApplyConfigurationRequestContext>.Descriptor,
            DisposeHttpRequest<ApplyConfigurationRequestContext>.Descriptor,

            /*
             * Configuration response processing:
             */
            DecompressResponseContent<ExtractConfigurationResponseContext>.Descriptor,
            ExtractJsonHttpResponse<ExtractConfigurationResponseContext>.Descriptor,
            ExtractWwwAuthenticateHeader<ExtractConfigurationResponseContext>.Descriptor,
            ValidateHttpResponse<ExtractConfigurationResponseContext>.Descriptor,
            DisposeHttpResponse<ExtractConfigurationResponseContext>.Descriptor,

            /*
             * Cryptography request processing:
             */
            CreateHttpClient<PrepareJsonWebKeySetRequestContext>.Descriptor,
            PrepareGetHttpRequest<PrepareJsonWebKeySetRequestContext>.Descriptor,
            AttachHttpVersion<PrepareJsonWebKeySetRequestContext>.Descriptor,
            AttachJsonAcceptHeaders<PrepareJsonWebKeySetRequestContext>.Descriptor,
            AttachUserAgentHeader<PrepareJsonWebKeySetRequestContext>.Descriptor,
            AttachFromHeader<PrepareJsonWebKeySetRequestContext>.Descriptor,
            AttachHttpParameters<PrepareJsonWebKeySetRequestContext>.Descriptor,
            SendHttpRequest<ApplyJsonWebKeySetRequestContext>.Descriptor,
            DisposeHttpRequest<ApplyJsonWebKeySetRequestContext>.Descriptor,

            /*
             * Configuration response processing:
             */
            DecompressResponseContent<ExtractJsonWebKeySetResponseContext>.Descriptor,
            ExtractJsonHttpResponse<ExtractJsonWebKeySetResponseContext>.Descriptor,
            ExtractWwwAuthenticateHeader<ExtractJsonWebKeySetResponseContext>.Descriptor,
            ValidateHttpResponse<ExtractJsonWebKeySetResponseContext>.Descriptor,
            DisposeHttpResponse<ExtractJsonWebKeySetResponseContext>.Descriptor
        ]);
    }
}
