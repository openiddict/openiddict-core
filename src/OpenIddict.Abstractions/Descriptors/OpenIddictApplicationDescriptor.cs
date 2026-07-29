using System.Globalization;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents an OpenIddict application descriptor.
/// </summary>
public class OpenIddictApplicationDescriptor
{
    /// <summary>
    /// Gets or sets the application type of the application.
    /// </summary>
    public string? ApplicationType { get; set; }

    /// <summary>
    /// Gets or sets the client identifier of the application.
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// Gets or sets the client secret of the application.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Note: depending on the application manager used to create this instance,
    /// this property may be hashed or encrypted for security reasons.
    /// </para>
    /// <para>
    /// Note: client authentication based on shared secrets is not recommended and should
    /// only be used for backward compatibility with legacy applications that only support
    /// client secrets. When possible, consider using public/private key pairs or TLS client
    /// certificates instead, as these client authentication methods are significantly safer.
    /// </para>
    /// </remarks>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets the client type of the application.
    /// </summary>
    public string? ClientType { get; set; }

    /// <summary>
    /// Gets or sets the consent type of the application.
    /// </summary>
    public string? ConsentType { get; set; }

    /// <summary>
    /// Gets or sets the display name of the application.
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Gets the localized display names of the application.
    /// </summary>
    public Dictionary<CultureInfo, string> DisplayNames { get; } = [];

    /// <summary>
    /// Gets or sets the JSON Web Key Set of the application.
    /// </summary>
    public JsonWebKeySet? JsonWebKeySet { get; set; }

    /// <summary>
    /// Gets the permissions of the application.
    /// </summary>
    public HashSet<string> Permissions { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the post-logout redirect URIs of the application.
    /// </summary>
    public HashSet<Uri> PostLogoutRedirectUris { get; } = [];

    /// <summary>
    /// Gets the additional properties of the application.
    /// </summary>
    public Dictionary<string, JsonElement> Properties { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the redirect URIs of the application.
    /// </summary>
    public HashSet<Uri> RedirectUris { get; } = [];

    /// <summary>
    /// Gets the requirements of the application.
    /// </summary>
    public HashSet<string> Requirements { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the settings of the application.
    /// </summary>
    public Dictionary<string, string> Settings { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Adds audience permissions for all the specified <paramref name="audiences"/>.
    /// </summary>
    /// <param name="audiences">The audiences for which audience permissions will be added.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="audiences"/> is <see langword="null"/>.</exception>
    public OpenIddictApplicationDescriptor AddAudiencePermissions(params string[] audiences)
    {
        ArgumentNullException.ThrowIfNull(audiences);

        foreach (var audience in audiences)
        {
            Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Audience + audience);
        }

        return this;
    }

    /// <summary>
    /// Adds grant type permissions for all the specified <paramref name="types"/>.
    /// </summary>
    /// <param name="types">The grant types for which grant types permissions will be added.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="types"/> is <see langword="null"/>.</exception>
    public OpenIddictApplicationDescriptor AddGrantTypePermissions(params string[] types)
    {
        ArgumentNullException.ThrowIfNull(types);

        foreach (var type in types)
        {
            Permissions.Add(OpenIddictConstants.Permissions.Prefixes.GrantType + type);
        }

        return this;
    }

    /// <summary>
    /// Adds resource permissions for all the specified <paramref name="resources"/>.
    /// </summary>
    /// <param name="resources">The resources for which resource permissions will be added.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="resources"/> is <see langword="null"/>.</exception>
    public OpenIddictApplicationDescriptor AddResourcePermissions(params string[] resources)
    {
        ArgumentNullException.ThrowIfNull(resources);

        foreach (var resource in resources)
        {
            Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Resource + resource);
        }

        return this;
    }

    /// <summary>
    /// Adds scope permissions for all the specified <paramref name="scopes"/>.
    /// </summary>
    /// <param name="scopes">The scopes for which scope permissions will be added.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="scopes"/> is <see langword="null"/>.</exception>
    public OpenIddictApplicationDescriptor AddScopePermissions(params string[] scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);

        foreach (var scope in scopes)
        {
            Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
        }

        return this;
    }

    /// <summary>
    /// Configures the application to use the specified access token <paramref name="lifetime"/>.
    /// </summary>
    /// <param name="lifetime">The access token lifetime or <see langword="null"/> to remove the stored value.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    public OpenIddictApplicationDescriptor SetAccessTokenLifetime(TimeSpan? lifetime)
    {
        if (lifetime is not null)
        {
            Settings[OpenIddictConstants.Settings.TokenLifetimes.AccessToken] =
                lifetime.Value.ToString("c", CultureInfo.InvariantCulture);
        }

        else
        {
            Settings.Remove(OpenIddictConstants.Settings.TokenLifetimes.AccessToken);
        }

        return this;
    }

    /// <summary>
    /// Configures the application to use the specified authorization code <paramref name="lifetime"/>.
    /// </summary>
    /// <param name="lifetime">The authorization code lifetime or <see langword="null"/> to remove the stored value.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    public OpenIddictApplicationDescriptor SetAuthorizationCodeLifetime(TimeSpan? lifetime)
    {
        if (lifetime is not null)
        {
            Settings[OpenIddictConstants.Settings.TokenLifetimes.AuthorizationCode] =
                lifetime.Value.ToString("c", CultureInfo.InvariantCulture);
        }

        else
        {
            Settings.Remove(OpenIddictConstants.Settings.TokenLifetimes.AuthorizationCode);
        }

        return this;
    }

    /// <summary>
    /// Configures the application to use the specified device code <paramref name="lifetime"/>.
    /// </summary>
    /// <param name="lifetime">The device code lifetime or <see langword="null"/> to remove the stored value.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    public OpenIddictApplicationDescriptor SetDeviceCodeLifetime(TimeSpan? lifetime)
    {
        if (lifetime is not null)
        {
            Settings[OpenIddictConstants.Settings.TokenLifetimes.DeviceCode] =
                lifetime.Value.ToString("c", CultureInfo.InvariantCulture);
        }

        else
        {
            Settings.Remove(OpenIddictConstants.Settings.TokenLifetimes.DeviceCode);
        }

        return this;
    }

    /// <summary>
    /// Configures the application to use the specified identity token <paramref name="lifetime"/>.
    /// </summary>
    /// <param name="lifetime">The identity token lifetime or <see langword="null"/> to remove the stored value.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    public OpenIddictApplicationDescriptor SetIdentityTokenLifetime(TimeSpan? lifetime)
    {
        if (lifetime is not null)
        {
            Settings[OpenIddictConstants.Settings.TokenLifetimes.IdentityToken] =
                lifetime.Value.ToString("c", CultureInfo.InvariantCulture);
        }

        else
        {
            Settings.Remove(OpenIddictConstants.Settings.TokenLifetimes.IdentityToken);
        }

        return this;
    }

    /// <summary>
    /// Configures the application to use the specified issued token <paramref name="lifetime"/>.
    /// </summary>
    /// <param name="lifetime">The issued token lifetime or <see langword="null"/> to remove the stored value.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    public OpenIddictApplicationDescriptor SetIssuedTokenLifetime(TimeSpan? lifetime)
    {
        if (lifetime is not null)
        {
            Settings[OpenIddictConstants.Settings.TokenLifetimes.IssuedToken] =
                lifetime.Value.ToString("c", CultureInfo.InvariantCulture);
        }

        else
        {
            Settings.Remove(OpenIddictConstants.Settings.TokenLifetimes.IssuedToken);
        }

        return this;
    }

    /// <summary>
    /// Configures the application to use the specified refresh token <paramref name="lifetime"/>.
    /// </summary>
    /// <param name="lifetime">The refresh token lifetime or <see langword="null"/> to remove the stored value.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    public OpenIddictApplicationDescriptor SetRefreshTokenLifetime(TimeSpan? lifetime)
    {
        if (lifetime is not null)
        {
            Settings[OpenIddictConstants.Settings.TokenLifetimes.RefreshToken] =
                lifetime.Value.ToString("c", CultureInfo.InvariantCulture);
        }

        else
        {
            Settings.Remove(OpenIddictConstants.Settings.TokenLifetimes.RefreshToken);
        }

        return this;
    }

    /// <summary>
    /// Configures the application to use the specified request token <paramref name="lifetime"/>.
    /// </summary>
    /// <param name="lifetime">The request token lifetime or <see langword="null"/> to remove the stored value.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    public OpenIddictApplicationDescriptor SetRequestTokenLifetime(TimeSpan? lifetime)
    {
        if (lifetime is not null)
        {
            Settings[OpenIddictConstants.Settings.TokenLifetimes.RequestToken] =
                lifetime.Value.ToString("c", CultureInfo.InvariantCulture);
        }

        else
        {
            Settings.Remove(OpenIddictConstants.Settings.TokenLifetimes.RequestToken);
        }

        return this;
    }

    /// <summary>
    /// Configures the application to use the specified user code <paramref name="lifetime"/>.
    /// </summary>
    /// <param name="lifetime">The user code lifetime or <see langword="null"/> to remove the stored value.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    public OpenIddictApplicationDescriptor SetUserCodeLifetime(TimeSpan? lifetime)
    {
        if (lifetime is not null)
        {
            Settings[OpenIddictConstants.Settings.TokenLifetimes.UserCode] =
                lifetime.Value.ToString("c", CultureInfo.InvariantCulture);
        }

        else
        {
            Settings.Remove(OpenIddictConstants.Settings.TokenLifetimes.UserCode);
        }

        return this;
    }

    /// <summary>
    /// Removes all the audience permissions corresponding to the specified <paramref name="audiences"/>.
    /// </summary>
    /// <param name="audiences">The audiences for which audience permissions will be removed.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="audiences"/> is <see langword="null"/>.</exception>
    public OpenIddictApplicationDescriptor RemoveAudiencePermissions(params string[] audiences)
    {
        ArgumentNullException.ThrowIfNull(audiences);

        foreach (var audience in audiences)
        {
            Permissions.Remove(OpenIddictConstants.Permissions.Prefixes.Audience + audience);
        }

        return this;
    }

    /// <summary>
    /// Removes all the grant type permissions corresponding to the specified <paramref name="types"/>.
    /// </summary>
    /// <param name="types">The grant types for which grant types permissions will be removed.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="types"/> is <see langword="null"/>.</exception>
    public OpenIddictApplicationDescriptor RemoveGrantTypePermissions(params string[] types)
    {
        ArgumentNullException.ThrowIfNull(types);

        foreach (var type in types)
        {
            Permissions.Remove(OpenIddictConstants.Permissions.Prefixes.GrantType + type);
        }

        return this;
    }

    /// <summary>
    /// Removes all the resource permissions corresponding to the specified <paramref name="resources"/>.
    /// </summary>
    /// <param name="resources">The resources for which resource permissions will be added.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="resources"/> is <see langword="null"/>.</exception>
    public OpenIddictApplicationDescriptor RemoveResourcePermissions(params string[] resources)
    {
        ArgumentNullException.ThrowIfNull(resources);

        foreach (var resource in resources)
        {
            Permissions.Remove(OpenIddictConstants.Permissions.Prefixes.Resource + resource);
        }

        return this;
    }

    /// <summary>
    /// Removes all the scope permissions corresponding to the specified <paramref name="scopes"/>.
    /// </summary>
    /// <param name="scopes">The scopes for which scope permissions will be added.</param>
    /// <returns>The <see cref="OpenIddictApplicationDescriptor"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="scopes"/> is <see langword="null"/>.</exception>
    public OpenIddictApplicationDescriptor RemoveScopePermissions(params string[] scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);

        foreach (var scope in scopes)
        {
            Permissions.Remove(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
        }

        return this;
    }
}
