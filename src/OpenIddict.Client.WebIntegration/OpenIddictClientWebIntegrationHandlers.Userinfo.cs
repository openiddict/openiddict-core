/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers;
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
            AttachNonStandardFieldParameter.Descriptor,

            /*
             * Userinfo response extraction:
             */
            UnwrapUserinfoResponse.Descriptor);

        /// <summary>
        /// Contains the logic responsible for attaching non-standard field parameters for the providers that require it.
        /// </summary>
        public class AttachNonStandardFieldParameter : IOpenIddictClientHandler<PrepareUserinfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareUserinfoRequestContext>()
                    .UseSingletonHandler<AttachNonStandardFieldParameter>()
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

                // Some providers are known to limit the number of fields returned by their userinfo endpoint
                // but allow returning additional information using a special parameter (generally called "fields")
                // that determines what fields will be returned as part of the userinfo response. This handler is
                // responsible for resolving the fields from the provider settings and attaching them to the request.

                if (context.Registration.GetProviderName() is Providers.Twitter)
                {
                    var options = context.Registration.GetTwitterOptions();

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

                var parameter = context.Registration.GetProviderName() switch
                {
                    Providers.Twitter => "data",

                    _ => null
                };

                if (!string.IsNullOrEmpty(parameter))
                {
                    context.Response = new OpenIddictResponse(context.Response[parameter]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334(parameter)));
                }

                return default;
            }
        }
    }
}
