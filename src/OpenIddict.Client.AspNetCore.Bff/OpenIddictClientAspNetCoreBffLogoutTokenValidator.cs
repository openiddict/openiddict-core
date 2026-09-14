/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static OpenIddict.Client.AspNetCore.Bff.OpenIddictClientAspNetCoreBffModels;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Validates the logout tokens sent to the back-channel logout endpoint, as defined by
/// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation">OpenID Connect Back-Channel Logout 1.0</see>.
/// </summary>
/// <remarks>
/// Note: the validation logic is delegated to the OpenIddict client stack
/// (see <see cref="OpenIddictClientService.AuthenticateWithLogoutTokenAsync"/>).
/// </remarks>
internal sealed class OpenIddictClientAspNetCoreBffLogoutTokenValidator
{
    private readonly ILogger<OpenIddictClientAspNetCoreBffLogoutTokenValidator> _logger;
    private readonly IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions> _options;
    private readonly OpenIddictClientService _service;

    public OpenIddictClientAspNetCoreBffLogoutTokenValidator(
        ILogger<OpenIddictClientAspNetCoreBffLogoutTokenValidator> logger,
        IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions> options,
        OpenIddictClientService service)
    {
        _logger = logger;
        _options = options;
        _service = service;
    }

    /// <summary>
    /// Validates the specified logout token.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="token">The logout token.</param>
    /// <returns>The back-channel logout notification, or <see langword="null"/> if the token is invalid.</returns>
    public async ValueTask<BackchannelLogoutNotification?> ValidateAsync(HttpContext context, string token)
    {
        OpenIddictClientModels.LogoutTokenAuthenticationResult result;

        try
        {
            result = await _service.AuthenticateWithLogoutTokenAsync(new()
            {
                CancellationToken = context.RequestAborted,
                LogoutToken = token,
                // Note: logout tokens without an "exp" claim are only accepted if they were
                // issued during the replay cache window configured in the BFF options.
                MaximumAge = _options.CurrentValue.LogoutTokenReplayCacheLifetime,
                // Note: for backward compatibility, the BFF endpoint doesn't require the "exp" claim
                // (which was not required by early drafts of OpenID Connect Back-Channel Logout 1.0).
                RequireExpiration = false
            });
        }

        catch (ProtocolException exception)
        {
            _logger.LogInformation(6320, SR.GetResourceString(SR.ID6320), exception.ErrorDescription ?? exception.Error);

            return null;
        }

        Debug.Assert(result.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));

        var issuer = result.Issuer.AbsoluteUri;

        _logger.LogInformation(6321, SR.GetResourceString(SR.ID6321), issuer, result.Subject, result.SessionId);

        return new BackchannelLogoutNotification
        {
            HttpContext = context,
            Issuer = issuer,
            Principal = result.LogoutTokenPrincipal,
            Registration = result.Registration,
            SessionId = result.SessionId,
            Subject = result.Subject
        };
    }
}
