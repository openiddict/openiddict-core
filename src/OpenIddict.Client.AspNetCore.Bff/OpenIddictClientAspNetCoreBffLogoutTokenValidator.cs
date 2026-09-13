/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using static OpenIddict.Client.AspNetCore.Bff.OpenIddictClientAspNetCoreBffModels;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Validates the logout tokens sent to the back-channel logout endpoint, as defined by
/// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation">OpenID Connect Back-Channel Logout 1.0</see>.
/// </summary>
internal sealed class OpenIddictClientAspNetCoreBffLogoutTokenValidator
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _identifiers = new(StringComparer.Ordinal);
    private readonly ILogger<OpenIddictClientAspNetCoreBffLogoutTokenValidator> _logger;
    private readonly IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions> _options;
    private readonly IOptionsMonitor<OpenIddictClientOptions> _clientOptions;
    private readonly OpenIddictClientService _service;

    public OpenIddictClientAspNetCoreBffLogoutTokenValidator(
        ILogger<OpenIddictClientAspNetCoreBffLogoutTokenValidator> logger,
        IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions> options,
        IOptionsMonitor<OpenIddictClientOptions> clientOptions,
        OpenIddictClientService service)
    {
        _logger = logger;
        _options = options;
        _clientOptions = clientOptions;
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
        var handler = _clientOptions.CurrentValue.JsonWebTokenHandler;
        if (!handler.CanReadToken(token))
        {
            return Fail("the token is not a JSON Web Token.");
        }

        var unvalidated = handler.ReadJsonWebToken(token);
        if (!Uri.TryCreate(unvalidated.Issuer, UriKind.Absolute, out var issuer))
        {
            return Fail("the issuer is missing or invalid.");
        }

        // Resolve the client registration using the issuer and the audiences of the logout token.
        // Note: the audiences are used to disambiguate registrations sharing the same issuer.
        var audiences = unvalidated.Audiences.ToHashSet(StringComparer.Ordinal);
        var registrations = (await _service.GetClientRegistrationsAsync(context.RequestAborted))
            .Where(registration => registration.Issuer is not null && !string.IsNullOrEmpty(registration.ClientId) &&
                string.Equals(registration.Issuer.AbsoluteUri.TrimEnd('/'), issuer.AbsoluteUri.TrimEnd('/'), StringComparison.Ordinal) &&
                audiences.Contains(registration.ClientId))
            .ToList();

        if (registrations is not [OpenIddictClientRegistration registration])
        {
            return Fail("no unique client registration matches the issuer and audiences.");
        }

        var configuration = await _service.GetServerConfigurationByRegistrationIdAsync(
            registration.RegistrationId!, context.RequestAborted);

        var parameters = registration.TokenValidationParameters.Clone();
        var uri = (configuration.Issuer ?? registration.Issuer!).AbsoluteUri;

        parameters.ValidIssuers = [uri, uri.TrimEnd('/')];
        parameters.ValidateIssuer = true;
        parameters.ValidAudiences = [registration.ClientId!];
        parameters.ValidateAudience = true;
        parameters.IssuerSigningKeys = parameters.IssuerSigningKeys?.Concat(configuration.SigningKeys) ?? configuration.SigningKeys;
        parameters.ValidTypes =
        [
            JsonWebTokenTypes.LogoutToken,
            JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.LogoutToken,
            JsonWebTokenTypes.GenericJsonWebToken
        ];

        // Note: "exp" was not required by early versions of the specification.
        parameters.RequireExpirationTime = false;
        parameters.ValidateLifetime = true;

        var result = await handler.ValidateTokenAsync(token, parameters);
        if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt)
        {
            return Fail(result.Exception?.Message ?? "the token cannot be validated.");
        }

        if (!jwt.TryGetPayloadValue<JsonElement>(Claims.Events, out var events) || events.ValueKind is not JsonValueKind.Object ||
            !events.TryGetProperty(OpenIddictClientAspNetCoreBffConstants.Events.BackchannelLogout, out var value) ||
            value.ValueKind is not JsonValueKind.Object)
        {
            return Fail("the events claim is missing or invalid.");
        }

        if (jwt.TryGetPayloadValue<object>(Claims.Nonce, out _))
        {
            return Fail("the token contains a nonce claim.");
        }

        if (!jwt.TryGetPayloadValue<long>(Claims.IssuedAt, out _))
        {
            return Fail("the iat claim is missing.");
        }

        var subject = jwt.TryGetPayloadValue<string>(Claims.Subject, out var sub) && !string.IsNullOrEmpty(sub) ? sub : null;
        var session = jwt.TryGetPayloadValue<string>(Claims.SessionId, out var sid) && !string.IsNullOrEmpty(sid) ? sid : null;
        if (subject is null && session is null)
        {
            return Fail("the sub and sid claims are both missing.");
        }

        if (string.IsNullOrEmpty(jwt.Id))
        {
            return Fail("the jti claim is missing.");
        }

        // Prevent replay attacks by rejecting logout tokens whose identifier was already seen.
        var now = _clientOptions.CurrentValue.TimeProvider.GetUtcNow();
        var expiration = now + _options.CurrentValue.LogoutTokenReplayCacheLifetime;
        if (jwt.ValidTo > DateTime.MinValue && new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero) > expiration)
        {
            expiration = new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero);
        }

        foreach (var entry in _identifiers)
        {
            if (entry.Value <= now)
            {
                _identifiers.TryRemove(entry);
            }
        }

        if (!_identifiers.TryAdd(string.Concat(uri, "\n", jwt.Id), expiration))
        {
            return Fail("the token was already used.");
        }

        _logger.LogInformation(6321, SR.GetResourceString(SR.ID6321), uri, subject, session);

        return new BackchannelLogoutNotification
        {
            HttpContext = context,
            Issuer = uri,
            Principal = new ClaimsPrincipal(result.ClaimsIdentity),
            Registration = registration,
            SessionId = session,
            Subject = subject
        };

        BackchannelLogoutNotification? Fail(string reason)
        {
            _logger.LogInformation(6320, SR.GetResourceString(SR.ID6320), reason);

            return null;
        }
    }
}
