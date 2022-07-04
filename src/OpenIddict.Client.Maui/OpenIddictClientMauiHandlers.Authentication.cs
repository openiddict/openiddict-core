/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Text;

namespace OpenIddict.Client.Maui;

public static partial class OpenIddictClientMauiHandlers
{
    public static class Authentication
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authorization request processing:
             */
            ProcessQueryRequest.Descriptor,

            /*
             * Redirection request extraction:
             */
            ExtractActivationParameters<ExtractRedirectionRequestContext>.Descriptor,

            /*
             * Redirection response handling:
             */
            ProcessResponse<ApplyRedirectionResponseContext>.Descriptor);

        /// <summary>
        /// Contains the logic responsible for initiating authorization requests using the system browser.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by MAUI.
        /// </summary>
        public class ProcessQueryRequest : IOpenIddictClientHandler<ApplyAuthorizationRequestContext>
        {
            private readonly IBrowser _browser;

            public ProcessQueryRequest()
                : this(Browser.Default)
            {
            }

            public ProcessQueryRequest(IBrowser browser)
                => _browser = browser ?? throw new ArgumentNullException(nameof(browser));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyAuthorizationRequestContext>()
                    .AddFilter<RequireMauiApplication>()
                    .UseSingletonHandler<ProcessQueryRequest>()
                    .SetOrder(50_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ApplyAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

                var builder = new StringBuilder();

                foreach (var (key, value) in
                    from parameter in context.Transaction.Request.GetParameters()
                    let values = (string?[]?) parameter.Value
                    where values is not null
                    from value in values
                    where !string.IsNullOrEmpty(value)
                    select (parameter.Key, Value: value))
                {
                    if (builder.Length > 0)
                    {
                        builder.Append('&');
                    }

                    builder.Append(Uri.EscapeDataString(key));
                    builder.Append('=');
                    builder.Append(Uri.EscapeDataString(value));
                }

                var uri = new UriBuilder(context.AuthorizationEndpoint) { Query = builder.ToString() }.Uri;
                await _browser.OpenAsync(uri, BrowserLaunchMode.SystemPreferred);
            }
        }
    }
}
