/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.Saml.AspNetCore;

/// <summary>
/// Decorates the <see cref="IAuthenticationSchemeProvider"/> registered in the DI container to dynamically
/// resolve forwarded authentication schemes corresponding to the provider names of the SAML registrations
/// returned by the <see cref="IOpenIddictClientSamlRegistrationProvider"/> implementations.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictClientSamlAspNetCoreSchemeProvider : IAuthenticationSchemeProvider
{
    private readonly IAuthenticationSchemeProvider _inner;
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSamlAspNetCoreSchemeProvider"/> class.
    /// </summary>
    /// <param name="inner">The decorated scheme provider.</param>
    /// <param name="provider">The service provider.</param>
    public OpenIddictClientSamlAspNetCoreSchemeProvider(IAuthenticationSchemeProvider inner, IServiceProvider provider)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <inheritdoc/>
    public void AddScheme(AuthenticationScheme scheme) => _inner.AddScheme(scheme);

    /// <inheritdoc/>
    public bool TryAddScheme(AuthenticationScheme scheme) => _inner.TryAddScheme(scheme);

    /// <inheritdoc/>
    public void RemoveScheme(string name) => _inner.RemoveScheme(name);

    /// <inheritdoc/>
    public async Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync()
    {
        var schemes = (await _inner.GetAllSchemesAsync()).ToList();

        if (IsForwardingEnabled())
        {
            // Note: the lookups are cached by the SAML service (see OpenIddictClientSamlOptions.DynamicRegistrationCacheLifetime).
            var registrations = await GetService().GetRegistrationsAsync(CancellationToken.None);

            foreach (var group in registrations
                .Where(static registration => !string.IsNullOrEmpty(registration.ProviderName))
                .GroupBy(static registration => registration.ProviderName!, StringComparer.Ordinal)
                .Where(static group => group.Distinct().Count() is 1))
            {
                if (!schemes.Exists(scheme => string.Equals(scheme.Name, group.Key, StringComparison.Ordinal)))
                {
                    schemes.Add(CreateScheme(group.First()));
                }
            }
        }

        return schemes;
    }

    /// <inheritdoc/>
    public Task<AuthenticationScheme?> GetDefaultAuthenticateSchemeAsync() => _inner.GetDefaultAuthenticateSchemeAsync();

    /// <inheritdoc/>
    public Task<AuthenticationScheme?> GetDefaultChallengeSchemeAsync() => _inner.GetDefaultChallengeSchemeAsync();

    /// <inheritdoc/>
    public Task<AuthenticationScheme?> GetDefaultForbidSchemeAsync() => _inner.GetDefaultForbidSchemeAsync();

    /// <inheritdoc/>
    public Task<AuthenticationScheme?> GetDefaultSignInSchemeAsync() => _inner.GetDefaultSignInSchemeAsync();

    /// <inheritdoc/>
    public Task<AuthenticationScheme?> GetDefaultSignOutSchemeAsync() => _inner.GetDefaultSignOutSchemeAsync();

    /// <inheritdoc/>
    public Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync() => _inner.GetRequestHandlerSchemesAsync();

    /// <inheritdoc/>
    public async Task<AuthenticationScheme?> GetSchemeAsync(string name)
    {
        // Note: schemes explicitly registered in the authentication options always take precedence.
        if (await _inner.GetSchemeAsync(name) is AuthenticationScheme scheme)
        {
            return scheme;
        }

        if (string.IsNullOrEmpty(name) || !IsForwardingEnabled() ||
            string.Equals(name, OpenIddictClientSamlAspNetCoreDefaults.AuthenticationScheme, StringComparison.Ordinal))
        {
            return null;
        }

        // Resolve the registrations whose provider name matches the requested scheme: if a single
        // registration is found, return a forwarded scheme pointing to the SAML authentication handler.
        //
        // Note: the lookups (including negative lookups) are cached by the SAML service.
        return await GetService().GetRegistrationsByProviderNameAsync(name, CancellationToken.None) is [var registration]
            ? CreateScheme(registration) : null;
    }

    private OpenIddictClientSamlService GetService()
        => _provider.GetService<OpenIddictClientSamlService>() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0900));

    private bool IsForwardingEnabled() => _provider.GetService<IOptionsMonitor<OpenIddictClientSamlAspNetCoreOptions>>()?
        .CurrentValue.DisableAutomaticAuthenticationSchemeForwarding is false;

    private static AuthenticationScheme CreateScheme(OpenIddictClientSamlRegistration registration) => new(
        name       : registration.ProviderName!,
        displayName: registration.ProviderDisplayName,
        handlerType: typeof(OpenIddictClientSamlAspNetCoreForwarder));
}
