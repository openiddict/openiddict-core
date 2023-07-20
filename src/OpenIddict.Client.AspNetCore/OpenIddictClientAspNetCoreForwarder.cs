/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using Properties = OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Properties;

namespace OpenIddict.Client.AspNetCore;

/// <summary>
/// Provides the logic necessary to forward authentication operations
/// using the specified authentication scheme as the provider name.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictClientAspNetCoreForwarder : IAuthenticationHandler, IAuthenticationSignOutHandler
{
    private HttpContext _context = default!;
    private AuthenticationScheme _scheme = default!;

    /// <inheritdoc/>
    public async Task<AuthenticateResult> AuthenticateAsync()
        // Resolve the authentication result returned by the OpenIddict ASP.NET Core client host:
        // if the returned identity was created for the specified provider, return the result.
        //
        // Note: exceptions MUST NOT be caught to ensure they are properly surfaced to the caller
        // (e.g if AuthenticateAsync("[provider name]") is called from an unsupported endpoint).
        => await _context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme) switch
        {
            { Succeeded: true } result when
                result.Principal.FindFirst(Claims.Private.ProviderName)?.Value is string provider &&
                string.Equals(provider, _scheme.Name, StringComparison.Ordinal)
                => AuthenticateResult.Success(new AuthenticationTicket(result.Principal, result.Properties, _scheme.Name)),

            AuthenticateResult result => result,

            null or _ => AuthenticateResult.NoResult()
        };

    /// <inheritdoc/>
    public async Task ChallengeAsync(AuthenticationProperties? properties)
    {
        // Ensure no client registration information was attached to the authentication properties.
        if (properties is not null && (properties.Items.ContainsKey(Properties.Issuer) ||
                                       properties.Items.ContainsKey(Properties.ProviderName) ||
                                       properties.Items.ContainsKey(Properties.RegistrationId)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0417));
        }

        // Note: exceptions MUST NOT be caught to ensure they are properly surfaced to the caller.
        await _context.ChallengeAsync(
            scheme: OpenIddictClientAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(
                items: new Dictionary<string, string?>(properties?.Items ?? ImmutableDictionary.Create<string, string?>())
                {
                    [Properties.ProviderName] = _scheme.Name
                },
                parameters: properties?.Parameters));
    }

    /// <inheritdoc/>
    public async Task ForbidAsync(AuthenticationProperties? properties)
    {
        // Ensure no client registration information was attached to the authentication properties.
        if (properties is not null && (properties.Items.ContainsKey(Properties.Issuer) ||
                                       properties.Items.ContainsKey(Properties.ProviderName) ||
                                       properties.Items.ContainsKey(Properties.RegistrationId)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0417));
        }

        // Note: exceptions MUST NOT be caught to ensure they are properly surfaced to the caller.
        await _context.ForbidAsync(
            scheme: OpenIddictClientAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(
                items: new Dictionary<string, string?>(properties?.Items ?? ImmutableDictionary.Create<string, string?>())
                {
                    [Properties.ProviderName] = _scheme.Name
                },
                parameters: properties?.Parameters));
    }

    /// <inheritdoc/>
    public async Task SignOutAsync(AuthenticationProperties? properties)
    {
        // Ensure no client registration information was attached to the authentication properties.
        if (properties is not null && (properties.Items.ContainsKey(Properties.Issuer) ||
                                       properties.Items.ContainsKey(Properties.ProviderName) ||
                                       properties.Items.ContainsKey(Properties.RegistrationId)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0417));
        }

        // Note: exceptions MUST NOT be caught to ensure they are properly surfaced to the caller.
        await _context.SignOutAsync(
            scheme: OpenIddictClientAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(
                items: new Dictionary<string, string?>(properties?.Items ?? ImmutableDictionary.Create<string, string?>())
                {
                    [Properties.ProviderName] = _scheme.Name
                },
                parameters: properties?.Parameters));
    }

    /// <inheritdoc/>
    public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _scheme = scheme ?? throw new ArgumentNullException(nameof(scheme));

        return Task.CompletedTask;
    }
}
