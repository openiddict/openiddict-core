/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Globalization;
using System.Net.Http;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Server.SystemNetHttp;

/// <summary>
/// Contains the event handlers used by the OpenIddict server/System.Net.Http integration.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public static class OpenIddictServerSystemNetHttpHandlers
{
    public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
    [
        SendHttpBackchannelLogoutRequest.Descriptor
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
}
