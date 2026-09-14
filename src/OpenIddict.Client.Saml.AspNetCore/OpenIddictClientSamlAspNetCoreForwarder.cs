/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Properties = OpenIddict.Client.Saml.OpenIddictClientSamlConstants.Properties;

namespace OpenIddict.Client.Saml.AspNetCore;

/// <summary>
/// Forwards the authentication operations of the schemes named after SAML registration provider names
/// to the OpenIddict SAML authentication handler, attaching the provider name to the challenges.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictClientSamlAspNetCoreForwarder : IAuthenticationHandler
{
    private AuthenticationScheme? _scheme;
    private HttpContext? _context;

    /// <inheritdoc/>
    public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
    {
        _scheme = scheme ?? throw new ArgumentNullException(nameof(scheme));
        _context = context ?? throw new ArgumentNullException(nameof(context));

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public async Task<AuthenticateResult> AuthenticateAsync()
    {
        var (scheme, context) = GetState();

        var result = await context.AuthenticateAsync(OpenIddictClientSamlAspNetCoreDefaults.AuthenticationScheme);

        // Only return the principal if it was issued for a registration with the same provider name.
        if (result.Succeeded && !string.Equals(result.Properties?.Items.TryGetValue(Properties.ProviderName, out var name) is true
            ? name : null, scheme.Name, StringComparison.Ordinal))
        {
            return AuthenticateResult.NoResult();
        }

        return result;
    }

    /// <inheritdoc/>
    public Task ChallengeAsync(AuthenticationProperties? properties)
    {
        var (scheme, context) = GetState();

        properties ??= new AuthenticationProperties();

        if (properties.Items.ContainsKey(Properties.RegistrationId) || properties.Items.ContainsKey(Properties.ProviderName))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0905));
        }

        properties.Items[Properties.ProviderName] = scheme.Name;

        return context.ChallengeAsync(OpenIddictClientSamlAspNetCoreDefaults.AuthenticationScheme, properties);
    }

    /// <inheritdoc/>
    public Task ForbidAsync(AuthenticationProperties? properties)
        => GetState().Context.ForbidAsync(OpenIddictClientSamlAspNetCoreDefaults.AuthenticationScheme, properties);

    private (AuthenticationScheme Scheme, HttpContext Context) GetState()
        => (_scheme, _context) is (AuthenticationScheme scheme, HttpContext context)
            ? (scheme, context)
            : throw new InvalidOperationException(SR.GetResourceString(SR.ID0900));
}
