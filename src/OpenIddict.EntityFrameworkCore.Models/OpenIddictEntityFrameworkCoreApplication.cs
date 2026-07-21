/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.EntityFrameworkCore.Models;

/// <summary>
/// Represents an OpenIddict application.
/// </summary>
public class OpenIddictEntityFrameworkCoreApplication : OpenIddictEntityFrameworkCoreApplication<string, OpenIddictEntityFrameworkCoreAuthorization, OpenIddictEntityFrameworkCoreToken>
{
    public OpenIddictEntityFrameworkCoreApplication() => Id = Guid.NewGuid().ToString();
}

/// <summary>
/// Represents an OpenIddict application.
/// </summary>
public class OpenIddictEntityFrameworkCoreApplication<TKey> : OpenIddictEntityFrameworkCoreApplication<TKey, OpenIddictEntityFrameworkCoreAuthorization<TKey>, OpenIddictEntityFrameworkCoreToken<TKey>>
    where TKey : notnull, IEquatable<TKey>;

/// <summary>
/// Represents an OpenIddict application.
/// </summary>
[DebuggerDisplay("Id = {Id.ToString(),nq} ; ClientId = {ClientId,nq} ; ClientType = {ClientType,nq}")]
public class OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
    where TKey : notnull, IEquatable<TKey>
    where TAuthorization : class
    where TToken : class
{
    /// <summary>
    /// Gets or sets the application type of the application.
    /// </summary>
    public virtual string? ApplicationType { get; set; }

    /// <summary>
    /// Gets the list of the authorizations associated with the application.
    /// </summary>
    public virtual ICollection<TAuthorization> Authorizations { get; } = new HashSet<TAuthorization>();

    /// <summary>
    /// Gets or sets the client identifier of the application.
    /// </summary>
    public virtual string? ClientId { get; set; }

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
    public virtual string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets the client type of the application.
    /// </summary>
    public virtual string? ClientType { get; set; }

    /// <summary>
    /// Gets or sets the concurrency token of the application.
    /// </summary>
    public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the consent type of the application.
    /// </summary>
    public virtual string? ConsentType { get; set; }

    /// <summary>
    /// Gets or sets the display name of the application.
    /// </summary>
    public virtual string? DisplayName { get; set; }

    /// <summary>
    /// Gets or sets the localized display names of the application.
    /// </summary>
    public virtual IDictionary<string, string>? DisplayNames { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the application.
    /// </summary>
    public virtual TKey? Id { get; set; }

    /// <summary>
    /// Gets or sets the JSON Web Key Set of the application.
    /// </summary>
    public virtual JsonWebKeySet? JsonWebKeySet { get; set; }

    /// <summary>
    /// Gets or sets the permissions of the application.
    /// </summary>
    public virtual string[]? Permissions { get; set; }

    /// <summary>
    /// Gets or sets the post-logout redirect URIs of the application.
    /// </summary>
    public virtual string[]? PostLogoutRedirectUris { get; set; }

    /// <summary>
    /// Gets or sets the additional properties of the application.
    /// </summary>
    public virtual IDictionary<string, JsonElement>? Properties { get; set; }

    /// <summary>
    /// Gets or sets the redirect URIs of the application.
    /// </summary>
    public virtual string[]? RedirectUris { get; set; }

    /// <summary>
    /// Gets or sets the requirements of the application.
    /// </summary>
    public virtual string[]? Requirements { get; set; }

    /// <summary>
    /// Gets or sets the settings of the application.
    /// </summary>
    public virtual IDictionary<string, string>? Settings { get; set; }

    /// <summary>
    /// Gets the list of the tokens associated with the application.
    /// </summary>
    public virtual ICollection<TToken> Tokens { get; } = new HashSet<TToken>();
}
