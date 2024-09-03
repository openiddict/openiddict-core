﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Server.Owin;

public static partial class OpenIddictServerOwinHandlers
{
    public static class Discovery
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Configuration request extraction:
             */
            ExtractGetRequest<ExtractConfigurationRequestContext>.Descriptor,

            /*
             * Configuration response processing:
             */
            AttachHttpResponseCode<ApplyConfigurationResponseContext>.Descriptor,
            AttachOwinResponseChallenge<ApplyConfigurationResponseContext>.Descriptor,
            SuppressFormsAuthenticationRedirect<ApplyConfigurationResponseContext>.Descriptor,
            AttachWwwAuthenticateHeader<ApplyConfigurationResponseContext>.Descriptor,
            ProcessJsonResponse<ApplyConfigurationResponseContext>.Descriptor,

            /*
             * Cryptography request extraction:
             */
            ExtractGetRequest<ExtractJsonWebKeySetRequestContext>.Descriptor,

            /*
             * Cryptography response processing:
             */
            AttachHttpResponseCode<ApplyJsonWebKeySetResponseContext>.Descriptor,
            AttachOwinResponseChallenge<ApplyJsonWebKeySetResponseContext>.Descriptor,
            SuppressFormsAuthenticationRedirect<ApplyJsonWebKeySetResponseContext>.Descriptor,
            AttachWwwAuthenticateHeader<ApplyJsonWebKeySetResponseContext>.Descriptor,
            ProcessJsonResponse<ApplyJsonWebKeySetResponseContext>.Descriptor
        ]);
    }
}
