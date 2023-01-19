/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using Microsoft.Extensions.Primitives;
using OpenIddict.Extensions;

namespace OpenIddict.Client.Windows;

public static partial class OpenIddictClientWindowsHandlers
{
    public static class Authentication
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authorization request processing:
             */
            LaunchSystemBrowser.Descriptor,

            /*
             * Redirection request extraction:
             */
            ExtractRequestUriParameters<ExtractRedirectionRequestContext>.Descriptor,

            /*
             * Redirection request handling:
             */
            ProcessResponse<HandleRedirectionRequestContext>.Descriptor,

            /*
             * Redirection response handling:
             */
            ProcessResponse<ApplyRedirectionResponseContext>.Descriptor);

        /// <summary>
        /// Contains the logic responsible for initiating authorization requests using the system browser.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by Windows.
        /// </summary>
        public class LaunchSystemBrowser : IOpenIddictClientHandler<ApplyAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyAuthorizationRequestContext>()
                    .AddFilter<RequireInteractiveSession>()
                    .UseSingletonHandler<LaunchSystemBrowser>()
                    .SetOrder(50_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

                var uri = OpenIddictHelpers.AddQueryStringParameters(
                    new Uri(context.AuthorizationEndpoint, UriKind.Absolute),
                    context.Transaction.Request.GetParameters().ToDictionary(
                        parameter => parameter.Key,
                        parameter => new StringValues((string?[]?) parameter.Value)));

                Process.Start(new ProcessStartInfo
                {
                    FileName = uri.AbsoluteUri,
                    UseShellExecute = true
                });

                return default;
            }
        }
    }
}
