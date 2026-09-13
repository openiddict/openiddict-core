/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using static OpenIddict.Client.AspNetCore.Bff.OpenIddictClientAspNetCoreBffModels;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Represents a <see cref="DelegatingHandler"/> attaching a user or client access token to outgoing requests.
/// </summary>
/// <remarks>
/// DPoP-bound tokens are sent with a DPoP proof. If the resource server returns a "use_dpop_nonce" error,
/// requests without content are sent again once with the nonce returned by the resource server.
/// </remarks>
public sealed class OpenIddictClientAspNetCoreBffAccessTokenHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _accessor;
    private readonly OpenIddictClientAspNetCoreBffTokenManager _manager;
    private readonly OpenIddictClientAspNetCoreBffTokenType _type;
    private readonly ClientAccessTokenRequest? _request;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientAspNetCoreBffAccessTokenHandler"/> class.
    /// </summary>
    /// <param name="accessor">The HTTP context accessor.</param>
    /// <param name="manager">The BFF token manager.</param>
    /// <param name="type">The type of access token to attach.</param>
    /// <param name="request">The client access token request, if applicable.</param>
    public OpenIddictClientAspNetCoreBffAccessTokenHandler(
        IHttpContextAccessor accessor,
        OpenIddictClientAspNetCoreBffTokenManager manager,
        OpenIddictClientAspNetCoreBffTokenType type,
        ClientAccessTokenRequest? request = null)
    {
        _accessor = accessor ?? throw new ArgumentNullException(nameof(accessor));
        _manager = manager ?? throw new ArgumentNullException(nameof(manager));
        _type = type;
        _request = request;
    }

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var token = await ResolveAccessTokenAsync(cancellationToken);
        if (token is null)
        {
            return await base.SendAsync(request, cancellationToken);
        }

        await _manager.AttachAccessTokenAsync(request, token, cancellationToken: cancellationToken);

        var response = await base.SendAsync(request, cancellationToken);

        // If the resource server requires a DPoP nonce, send the request again with the returned nonce.
        // Note: requests with content are never sent again, as the content may not be re-readable.
        if (request.Content is null && response.StatusCode is HttpStatusCode.Unauthorized &&
            string.Equals(token.TokenType, TokenTypes.DPoP, StringComparison.OrdinalIgnoreCase) &&
            response.Headers.TryGetValues(OpenIddictClientAspNetCoreBffConstants.Headers.DPoPNonce, out var values) &&
            values.FirstOrDefault() is { Length: > 0 } nonce &&
            response.Headers.WwwAuthenticate.Any(static header => header.Parameter?.Contains(
                Errors.UseDPoPNonce, StringComparison.Ordinal) is true))
        {
            response.Dispose();

            await _manager.AttachAccessTokenAsync(request, token, nonce: nonce, cancellationToken: cancellationToken);

            response = await base.SendAsync(request, cancellationToken);
        }

        return response;
    }

    private async ValueTask<AccessToken?> ResolveAccessTokenAsync(CancellationToken cancellationToken)
    {
        switch (_type)
        {
            case OpenIddictClientAspNetCoreBffTokenType.User or OpenIddictClientAspNetCoreBffTokenType.OptionalUser:
                return _accessor.HttpContext is HttpContext context ? await _manager.GetUserAccessTokenAsync(context) : null;

            case OpenIddictClientAspNetCoreBffTokenType.Client:
                return await _manager.GetClientAccessTokenAsync(_request, cancellationToken);

            case OpenIddictClientAspNetCoreBffTokenType.UserOrClient:
                return (_accessor.HttpContext is HttpContext value ? await _manager.GetUserAccessTokenAsync(value) : null)
                    ?? await _manager.GetClientAccessTokenAsync(_request, cancellationToken);

            default: return null;
        }
    }
}
