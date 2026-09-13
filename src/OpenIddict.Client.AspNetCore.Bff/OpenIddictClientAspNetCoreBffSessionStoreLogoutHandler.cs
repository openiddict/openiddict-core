/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static OpenIddict.Client.AspNetCore.Bff.OpenIddictClientAspNetCoreBffModels;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Removes the sessions matching a back-channel logout notification from the session
/// store attached to the BFF cookie scheme, when it implements <see cref="IOpenIddictClientAspNetCoreBffSessionStore"/>.
/// </summary>
public sealed class OpenIddictClientAspNetCoreBffSessionStoreLogoutHandler : IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler
{
    private readonly ILogger<OpenIddictClientAspNetCoreBffSessionStoreLogoutHandler> _logger;
    private readonly IOptionsMonitor<CookieAuthenticationOptions> _cookieOptions;
    private readonly IAuthenticationSchemeProvider _schemes;
    private readonly IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientAspNetCoreBffSessionStoreLogoutHandler"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="cookieOptions">The cookie authentication options.</param>
    /// <param name="schemes">The authentication scheme provider.</param>
    /// <param name="options">The BFF options.</param>
    public OpenIddictClientAspNetCoreBffSessionStoreLogoutHandler(
        ILogger<OpenIddictClientAspNetCoreBffSessionStoreLogoutHandler> logger,
        IOptionsMonitor<CookieAuthenticationOptions> cookieOptions,
        IAuthenticationSchemeProvider schemes,
        IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions> options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _cookieOptions = cookieOptions ?? throw new ArgumentNullException(nameof(cookieOptions));
        _schemes = schemes ?? throw new ArgumentNullException(nameof(schemes));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc/>
    public async ValueTask HandleAsync(BackchannelLogoutNotification notification, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(notification);

        var scheme = _options.CurrentValue.CookieScheme ?? (await _schemes.GetDefaultAuthenticateSchemeAsync())?.Name;
        if (string.IsNullOrEmpty(scheme) || string.IsNullOrEmpty(notification.Registration.RegistrationId))
        {
            return;
        }

        if (_cookieOptions.Get(scheme).SessionStore is not IOpenIddictClientAspNetCoreBffSessionStore store)
        {
            _logger.LogWarning(6322, SR.GetResourceString(SR.ID6322), scheme);

            return;
        }

        var count = await store.RemoveSessionsAsync(notification.Registration.RegistrationId,
            notification.Subject, notification.SessionId, cancellationToken);

        _logger.LogInformation(6323, SR.GetResourceString(SR.ID6323), count, scheme);
    }
}
