/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace OpenIddict.Validation.SystemNetHttp
{
    public static partial class OpenIddictValidationSystemNetHttpHandlers
    {
        public static class Introspection
        {
            public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Introspection request processing:
                 */
                PreparePostHttpRequest<PrepareIntrospectionRequestContext>.Descriptor,
                SendHttpRequest<ApplyIntrospectionRequestContext>.Descriptor,

                /*
                 * Introspection response processing:
                 */
                ExtractJsonHttpResponse<ExtractIntrospectionResponseContext>.Descriptor);
        }
    }
}
