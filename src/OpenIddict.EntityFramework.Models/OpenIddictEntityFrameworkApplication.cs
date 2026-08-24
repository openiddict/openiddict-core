/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace OpenIddict.EntityFramework.Models;

/// <summary>
/// Represents an OpenIddict application.
/// </summary>
public class OpenIddictEntityFrameworkApplication :
    OpenIddictEntityFrameworkApplication<string,
                                         OpenIddictEntityFrameworkAuthorization,
                                         OpenIddictEntityFrameworkSession,
                                         OpenIddictEntityFrameworkToken>
{
    public OpenIddictEntityFrameworkApplication() => Id = Guid.NewGuid().ToString();
}

/// <summary>
/// Represents an OpenIddict application.
/// </summary>
[DebuggerDisplay("Id = {Id.ToString(),nq} ; ClientId = {ClientId,nq} ; ClientType = {ClientType,nq}")]
public class OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TSession, TToken>
    where TKey : notnull, IEquatable<TKey>
    where TAuthorization : class
    where TSession : class
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
    /// Gets or sets the localized display names of the application, serialized as a JSON object.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Json)]
    public virtual string? DisplayNames { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the application.
    /// </summary>
    public virtual TKey? Id { get; set; }

    /// <summary>
    /// Gets or sets the JSON Web Key Set of the application, serialized as a JSON object.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Json)]
    public virtual string? JsonWebKeySet { get; set; }

    /// <summary>
    /// Gets or sets the permissions of the application, serialized as a JSON array.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Json)]
    public virtual string? Permissions { get; set; }

    /// <summary>
    /// Gets or sets the post-logout redirect URIs of the application, serialized as a JSON array.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Json)]
    public virtual string? PostLogoutRedirectUris { get; set; }

    /// <summary>
    /// Gets or sets the additional properties of the application, serialized as a JSON object.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Json)]
    public virtual string? Properties { get; set; }

    /// <summary>
    /// Gets or sets the redirect URIs of the application, serialized as a JSON array.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Json)]
    public virtual string? RedirectUris { get; set; }

    /// <summary>
    /// Gets or sets the requirements of the application, serialized as a JSON array.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Json)]
    public virtual string? Requirements { get; set; }

    /// <summary>
    /// Gets or sets the settings of the application, serialized as a JSON object.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Json)]
    public virtual string? Settings { get; set; }

    /// <summary>
    /// Gets the list of the sessions associated with the application.
    /// </summary>
    public virtual ICollection<TSession> Sessions { get; } = new HashSet<TSession>();

    /// <summary>
    /// Gets the list of the tokens associated with the application.
    /// </summary>
    public virtual ICollection<TToken> Tokens { get; } = new HashSet<TToken>();
}
