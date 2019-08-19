/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Threading.Tasks;
using JetBrains.Annotations;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.Owin.OpenIddictServerOwinHandlerFilters;

namespace OpenIddict.Server.Owin
{
    public static partial class OpenIddictServerOwinHandlers
    {
        public static class Exchange
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Token request extraction:
                 */
                ExtractPostRequest<ExtractTokenRequestContext>.Descriptor,
                ExtractBasicAuthenticationCredentials<ExtractTokenRequestContext>.Descriptor,

                /*
                 * Token request handling:
                 */
                EnablePassthroughMode.Descriptor,

                /*
                 * Token response processing:
                 */
                ProcessJsonResponse<ApplyTokenResponseContext>.Descriptor);

            /// <summary>
            /// Contains the logic responsible of enabling the pass-through mode for the received request.
            /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
            /// </summary>
            public class EnablePassthroughMode : IOpenIddictServerHandler<HandleTokenRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleTokenRequestContext>()
                        .AddFilter<RequireTokenEndpointPassthroughEnabled>()
                        .UseSingletonHandler<EnablePassthroughMode>()
                        .SetOrder(int.MaxValue - 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public Task HandleAsync([NotNull] HandleTokenRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    context.SkipRequest();

                    return Task.CompletedTask;
                }
            }
        }
    }
}
