/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Text.Json;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers.Userinfo;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class Userinfo
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Userinfo request preparation:
             */
            AttachAdditionalParameters.Descriptor,

            /*
             * Userinfo response extraction:
             */
            UnwrapUserinfoResponse.Descriptor);

        /// <summary>
        /// Contains the logic responsible for attaching additional parameters for the providers that require it.
        /// </summary>
        public class AttachAdditionalParameters : IOpenIddictClientHandler<PrepareUserinfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareUserinfoRequestContext>()
                    .UseSingletonHandler<AttachAdditionalParameters>()
                    .SetOrder(PrepareGetHttpRequest<PrepareUserinfoRequestContext>.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareUserinfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Request is not null, SR.GetResourceString(SR.ID4008));

                if (context.Registration.ProviderName is Providers.Twitter)
                {
                    var options = context.Registration.GetTwitterOptions();

                    // Twitter limits the number of fields returned by the userinfo endpoint
                    // but allows returning additional information using special parameters that
                    // determine what fields will be returned as part of the userinfo response.
                    context.Request["expansions"] = string.Join(",", options.Expansions);
                    context.Request["tweet.fields"] = string.Join(",", options.TweetFields);
                    context.Request["user.fields"] = string.Join(",", options.UserFields);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the userinfo response
        /// from nested JSON nodes (e.g "data") for the providers that require it.
        /// </summary>
        public class UnwrapUserinfoResponse : IOpenIddictClientHandler<ExtractUserinfoResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ExtractUserinfoResponseContext>()
                    .UseSingletonHandler<UnwrapUserinfoResponse>()
                    .SetOrder(ExtractJsonHttpResponse<ExtractUserinfoResponseContext>.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractUserinfoResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Response is not null, SR.GetResourceString(SR.ID4007));

                // Some providers are known to wrap their userinfo payloads in top-level JSON nodes
                // (generally named "d", "data" or "response"), which prevents the default extraction
                // logic from mapping the parameters to CLR claims. To work around that, this handler
                // is responsible for extracting the nested payload and replacing the userinfo response.

                context.Response = context.Registration.ProviderName switch
                {
                    // Twitter uses a nested object.
                    Providers.Twitter => (JsonElement) context.Response["data"]
                        is { ValueKind: JsonValueKind.Object } element ?
                        new(element) : throw new InvalidOperationException(SR.FormatID0334("data")),

                    _ => context.Response
                };

                return default;
            }
        }
    }
}
