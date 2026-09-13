/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Attaches the in-memory session store to the BFF cookie scheme (or to all the cookie schemes if no scheme was set).
/// </summary>
internal sealed class OpenIddictClientAspNetCoreBffSessionStoreConfiguration : IPostConfigureOptions<CookieAuthenticationOptions>
{
    private readonly IServiceProvider _provider;

    public OpenIddictClientAspNetCoreBffSessionStoreConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void PostConfigure(string? name, CookieAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var scheme = _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions>>().CurrentValue.CookieScheme;
        if (!string.IsNullOrEmpty(scheme) && !string.Equals(name, scheme, StringComparison.Ordinal))
        {
            return;
        }

        options.SessionStore ??= _provider.GetRequiredService<OpenIddictClientAspNetCoreBffMemorySessionStore>();
    }
}
