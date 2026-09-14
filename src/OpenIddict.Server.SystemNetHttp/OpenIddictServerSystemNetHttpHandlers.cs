/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server.SystemNetHttp;

/// <summary>
/// Contains the event handlers used by the OpenIddict server/System.Net.Http integration.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public static class OpenIddictServerSystemNetHttpHandlers
{
    public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
    [
        SendHttpBackchannelLogoutRequest.Descriptor,
        SendHttpBackchannelNotification.Descriptor
    ];

    /// <summary>
    /// Contains the logic responsible for sending back-channel logout requests using System.Net.Http,
    /// as defined by https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRequest.
    /// </summary>
    public sealed class SendHttpBackchannelLogoutRequest : IOpenIddictServerHandler<SendBackchannelLogoutRequestContext>
    {
        private readonly IHttpClientFactory _factory;

        public SendHttpBackchannelLogoutRequest(IHttpClientFactory factory)
            => _factory = factory ?? throw new ArgumentNullException(nameof(factory));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<SendBackchannelLogoutRequestContext>()
                .UseSingletonHandler<SendHttpBackchannelLogoutRequest>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(SendBackchannelLogoutRequestContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // If the request was already sent or rejected by another handler, don't send it again.
            if (context.IsSent || context.IsRejected)
            {
                return;
            }

            // Note: the logout token is sent as a "logout_token" form parameter using a POST request.
            using var request = new HttpRequestMessage(HttpMethod.Post, context.Uri)
            {
                Content = new FormUrlEncodedContent(
                [
                    new KeyValuePair<string, string>(Parameters.LogoutToken, context.LogoutToken)
                ])
            };

            var client = _factory.CreateClient(OpenIddictServerSystemNetHttpConstants.HttpClientName);

            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.CancellationToken);

            // Note: the client application is expected to return a 200 OK response when the logout succeeded
            // (a 204 No Content response is also accepted) and a 400 Bad Request response otherwise.
            if (!response.IsSuccessStatusCode)
            {
                context.Logger.LogInformation(6534, SR.GetResourceString(SR.ID6534), context.Uri, (int) response.StatusCode);

                context.Reject(
                    error: Errors.ServerError,
                    description: string.Concat(((int) response.StatusCode).ToString(CultureInfo.InvariantCulture), " ", response.ReasonPhrase));

                return;
            }

            context.IsSent = true;
        }
    }

    /// <summary>
    /// Contains the logic responsible for sending ping and push notifications
    /// to HTTP client notification endpoints using System.Net.Http.
    /// </summary>
    /// <remarks>
    /// See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2
    /// and https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.
    /// </remarks>
    public sealed class SendHttpBackchannelNotification : IOpenIddictServerHandler<SendBackchannelNotificationContext>
    {
        private readonly IHttpClientFactory _factory;
        private readonly IOptionsMonitor<OpenIddictServerSystemNetHttpOptions> _options;

        public SendHttpBackchannelNotification(
            IHttpClientFactory factory, IOptionsMonitor<OpenIddictServerSystemNetHttpOptions> options)
        {
            _factory = factory ?? throw new ArgumentNullException(nameof(factory));
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<SendBackchannelNotificationContext>()
                .UseSingletonHandler<SendHttpBackchannelNotification>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(SendBackchannelNotificationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // Only handle notifications sent to HTTP(S) endpoints (other transports may be registered by the application).
            if (!string.Equals(context.ClientNotificationEndpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(context.ClientNotificationEndpoint.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var client = _factory.CreateClient(OpenIddictServerSystemNetHttpConfiguration.HttpClientName)
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0604));

            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            }))
            {
                context.Notification.WriteTo(writer);
            }

            // The notification is sent as a JSON POST request authenticated using the client notification
            // token as a bearer token. For more information, see
            // https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2.
            using var request = new HttpRequestMessage(HttpMethod.Post, context.ClientNotificationEndpoint)
            {
                Content = new ByteArrayContent(stream.ToArray())
            };

            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.ClientNotificationToken);

            if (_options.CurrentValue.ProductInformation is ProductInfoHeaderValue information)
            {
                request.Headers.UserAgent.Add(information);
            }

            context.Logger.LogDebug(6411, SR.GetResourceString(SR.ID6411), context.ClientNotificationEndpoint, context.TokenDeliveryMode);

            try
            {
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.CancellationToken);

                // Note: the client notification endpoint SHOULD return a 204 status code but 200 is also accepted.
                // Redirections (that are never followed) and error status codes are treated as delivery failures.
                if (!response.IsSuccessStatusCode)
                {
                    context.Logger.LogInformation(6412, SR.GetResourceString(SR.ID6412),
                        context.ClientNotificationEndpoint, (int) response.StatusCode);

                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2307((int) response.StatusCode),
                        uri: SR.FormatID8000(SR.ID2307));

                    return;
                }
            }

            catch (Exception exception) when (exception is HttpRequestException ||
                (exception is OperationCanceledException && !context.CancellationToken.IsCancellationRequested))
            {
                context.Logger.LogInformation(6413, exception, SR.GetResourceString(SR.ID6413), context.ClientNotificationEndpoint);

                context.Reject(
                    error: Errors.ServerError,
                    description: SR.GetResourceString(SR.ID2308),
                    uri: SR.FormatID8000(SR.ID2308));

                return;
            }

            context.HandleRequest();
        }
    }
}
