/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
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
        /// </summary>
        public sealed class FetchClientIdMetadataDocument : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            private readonly IHttpClientFactory _factory;
            private readonly IOptionsMonitor<OpenIddictServerOptions> _serverOptions;
            private readonly IOptionsMonitor<OpenIddictServerSystemNetHttpOptions> _httpOptions;

            public FetchClientIdMetadataDocument(
                IHttpClientFactory factory,
                IOptionsMonitor<OpenIddictServerOptions> serverOptions,
                IOptionsMonitor<OpenIddictServerSystemNetHttpOptions> httpOptions)
            {
                _factory = factory ?? throw new ArgumentNullException(nameof(factory));
                _serverOptions = serverOptions ?? throw new ArgumentNullException(nameof(serverOptions));
                _httpOptions = httpOptions ?? throw new ArgumentNullException(nameof(httpOptions));
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    .AddFilter<RequireClientIdMetadataDocumentSupportEnabled>()
                    .UseScopedHandler<FetchClientIdMetadataDocument>()
                    // Run after ValidateAuthentication and before RestorePushedAuthorizationRequestParameters.
                    .SetOrder(OpenIddictServerHandlers.Authentication.ValidateAuthentication.Descriptor.Order + 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Only proceed if the transaction was flagged as requiring CIMD fetch.
                // This flag is set by the modified ValidateClientId handler (Phase 3) when
                // FindByClientIdAsync() returns null and the client_id is a valid CIMD URL.
                if (!context.Transaction.Properties.TryGetValue(
                    OpenIddictServerSystemNetHttpConstants.Properties.ClientIdMetadataDocumentFetchRequired, out var value) ||
                    value is not true)
                {
                    return;
                }

                var clientId = context.Transaction.Request?.ClientId;
                if (string.IsNullOrEmpty(clientId))
                {
                    return;
                }

                if (!Uri.TryCreate(clientId, UriKind.Absolute, out var clientUri) ||
                    !string.Equals(clientUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                {
                    context.Reject(
                        error: Errors.InvalidClient,
                        description: "The specified client_id is not a valid HTTPS URL.",
                        uri: null);

                    return;
                }

                var options = _serverOptions.CurrentValue;

                var assembly = typeof(OpenIddictServerSystemNetHttpOptions).Assembly.GetName();
                var client = _factory.CreateClient(assembly.Name!);

                    // Apply size limit and timeout from server options.
                    client.Timeout = options.ClientIdMetadataDocumentFetchTimeout;

                    using var request = new HttpRequestMessage(HttpMethod.Get, clientUri);
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                    // Attach User-Agent header if configured.
                    var httpOptions = _httpOptions.CurrentValue;
                    if (httpOptions.ProductInformation is not null)
                    {
                        request.Headers.UserAgent.Add(httpOptions.ProductInformation);
                    }

                    using var response = await client.SendAsync(request, context.CancellationToken);

                    if (!response.IsSuccessStatusCode)
                    {
                        context.Logger.LogWarning(
                            "The CIMD metadata document fetch for client_id '{ClientId}' failed with status code {StatusCode}.",
                            clientId, response.StatusCode);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: "The client_id metadata document could not be retrieved.",
                            uri: null);

                        return;
                    }

                    // Enforce size limit: read the response body with a size check.
                    var sizeLimit = options.ClientIdMetadataDocumentSizeLimit;
                    var content = response.Content;

#if SUPPORTS_STREAM_MEMORY_METHODS
                    using var stream = await content.ReadAsStreamAsync(context.CancellationToken);
#else
                    using var stream = await content.ReadAsStreamAsync();
#endif
                    var buffer = new byte[sizeLimit + 1];
                    var totalRead = 0;
                    int bytesRead;

                    while (totalRead < buffer.Length &&
                           (bytesRead = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead), context.CancellationToken)) > 0)
                    {
                        totalRead += bytesRead;
                    }

                    if (totalRead > sizeLimit)
                    {
                        context.Logger.LogWarning(
                            "The CIMD metadata document for client_id '{ClientId}' exceeds the maximum allowed size of {SizeLimit} bytes.",
                            clientId, sizeLimit);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: "The client_id metadata document exceeds the maximum allowed size.",
                            uri: null);

                        return;
                    }

                    // Parse the JSON metadata document.
                    JsonDocument document;
                    try
                    {
                        document = JsonDocument.Parse(buffer.AsMemory(0, totalRead));
                    }
                    catch (JsonException)
                    {
                        context.Logger.LogWarning(
                            "The CIMD metadata document for client_id '{ClientId}' is not valid JSON.",
                            clientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: "The client_id metadata document is not valid JSON.",
                            uri: null);

                        return;
                    }

                    // Validate that the document contains a client_id field matching the URL (exact string comparison).
                    if (!document.RootElement.TryGetProperty("client_id", out var clientIdElement) ||
                        clientIdElement.ValueKind != JsonValueKind.String ||
                        !string.Equals(clientIdElement.GetString(), clientId, StringComparison.Ordinal))
                    {
                        context.Logger.LogWarning(
                            "The CIMD metadata document's client_id field does not match the expected value '{ClientId}'.",
                            clientId);

                        context.Reject(
                            error: Errors.InvalidClient,
                            description: "The client_id in the metadata document does not match the requested client_id.",
                            uri: null);

                        document.Dispose();
                        return;
                    }

                    // Validate that the client does not use forbidden authentication methods.
                    // CIMD clients MUST NOT use client_secret_post, client_secret_basic, or client_secret_jwt.
                    if (document.RootElement.TryGetProperty("token_endpoint_auth_method", out var authMethodElement) &&
                        authMethodElement.ValueKind == JsonValueKind.String)
                    {
                        var authMethod = authMethodElement.GetString();
                        if (string.Equals(authMethod, "client_secret_post", StringComparison.Ordinal) ||
                            string.Equals(authMethod, "client_secret_basic", StringComparison.Ordinal) ||
                            string.Equals(authMethod, "client_secret_jwt", StringComparison.Ordinal))
                        {
                            context.Logger.LogWarning(
                                "The CIMD metadata document for client_id '{ClientId}' specifies a forbidden authentication method '{AuthMethod}'.",
                                clientId, authMethod);

                            context.Reject(
                                error: Errors.InvalidClient,
                                description: "The client_id metadata document specifies a forbidden authentication method.",
                                uri: null);

                            document.Dispose();
                            return;
                        }
                    }

                    // Store the parsed metadata document on the transaction properties for use by subsequent handlers.
                    context.Transaction.Properties[OpenIddictServerSystemNetHttpConstants.Properties.ClientIdMetadataDocument] = document;

                    context.Logger.LogInformation(
                        "The CIMD metadata document for client_id '{ClientId}' was successfully fetched and validated.",
                        clientId);
            }
        }
    }
}
