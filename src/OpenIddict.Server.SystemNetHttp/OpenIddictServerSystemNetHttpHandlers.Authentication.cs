/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Net.Http;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server.SystemNetHttp;

public static partial class OpenIddictServerSystemNetHttpHandlers
{
    public static class Authentication
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
        [
            FetchClientIdMetadataDocument.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for fetching the CIMD metadata document
        /// when the client_id is an HTTPS URL and no pre-registered client was found.
        /// This handler runs inside the <see cref="ProcessAuthenticationContext"/> pipeline,
        /// after <see cref="OpenIddictServerHandlers.ValidateClientId"/> and before
        /// <see cref="OpenIddictServerHandlers.ValidateClientType"/>, so that the CIMD
        /// context is populated for all endpoint types (authorize, token, etc.).
        /// </summary>
        public sealed class FetchClientIdMetadataDocument : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            private readonly OpenIddictServerSystemNetHttpCimdContext _cimdContext;
            private readonly IHttpClientFactory _factory;
            private readonly IOptionsMonitor<OpenIddictServerOptions> _serverOptions;
            private readonly IOptionsMonitor<OpenIddictServerSystemNetHttpOptions> _httpOptions;

            public FetchClientIdMetadataDocument(
                OpenIddictServerSystemNetHttpCimdContext cimdContext,
                IHttpClientFactory factory,
                IOptionsMonitor<OpenIddictServerOptions> serverOptions,
                IOptionsMonitor<OpenIddictServerSystemNetHttpOptions> httpOptions)
            {
                _cimdContext = cimdContext ?? throw new ArgumentNullException(nameof(cimdContext));
                _factory = factory ?? throw new ArgumentNullException(nameof(factory));
                _serverOptions = serverOptions ?? throw new ArgumentNullException(nameof(serverOptions));
                _httpOptions = httpOptions ?? throw new ArgumentNullException(nameof(httpOptions));
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireClientIdMetadataDocumentSupportEnabled>()
                    .UseScopedHandler<FetchClientIdMetadataDocument>()
                    // Run after ValidateClientId and before ValidateClientType.
                    .SetOrder(OpenIddictServerHandlers.ValidateClientId.Descriptor.Order + 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                await FetchAndValidateCimdDocumentAsync(context, _cimdContext, _factory, _serverOptions, _httpOptions);
            }
        }
    }
}
