/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Text.Json;

namespace OpenIddict.EntityFrameworkCore.Models;

/// <summary>
/// Represents an OpenIddict token.
/// </summary>
public class OpenIddictEntityFrameworkCoreToken : OpenIddictEntityFrameworkCoreToken<string, OpenIddictEntityFrameworkCoreApplication, OpenIddictEntityFrameworkCoreAuthorization>
{
    public OpenIddictEntityFrameworkCoreToken() => Id = Guid.NewGuid().ToString();
}

/// <summary>
/// Represents an OpenIddict token.
/// </summary>
public class OpenIddictEntityFrameworkCoreToken<TKey> : OpenIddictEntityFrameworkCoreToken<TKey, OpenIddictEntityFrameworkCoreApplication<TKey>, OpenIddictEntityFrameworkCoreAuthorization<TKey>>
    where TKey : notnull, IEquatable<TKey>;

/// <summary>
/// Represents an OpenIddict token.
/// </summary>
[DebuggerDisplay("Id = {Id.ToString(),nq} ; Subject = {Subject,nq} ; Type = {Type,nq} ; Status = {Status,nq}")]
public class OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
    where TKey : notnull, IEquatable<TKey>
    where TApplication : class
    where TAuthorization : class
{
    /// <summary>
    /// Gets or sets the application associated with the current token.
    /// </summary>
    public virtual TApplication? Application { get; set; }

    /// <summary>
    /// Gets or sets the authorization associated with the current token.
    /// </summary>
    public virtual TAuthorization? Authorization { get; set; }

    /// <summary>
    /// Gets or sets the concurrency token of the token.
    /// </summary>
    public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the UTC creation date of the token.
    /// </summary>
    public virtual DateTime? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the UTC expiration date of the token.
    /// </summary>
    public virtual DateTime? ExpirationDate { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the token.
    /// </summary>
    public virtual TKey? Id { get; set; }

    /// <summary>
    /// Gets or sets the payload of the token.
    /// </summary>
    /// <remarks>
    /// Note: this property is only used for reference tokens
    /// and may be hashed or encrypted for security reasons.
    /// </remarks>
    public virtual string? Payload { get; set; }

    /// <summary>
    /// Gets or sets the additional properties of the token.
    /// </summary>
    public virtual IDictionary<string, JsonElement>? Properties { get; set; }

    /// <summary>
    /// Gets or sets the UTC redemption date of the token.
    /// </summary>
    public virtual DateTime? RedemptionDate { get; set; }

    /// <summary>
    /// Gets or sets the reference identifier of the token.
    /// </summary>
    /// <remarks>
    /// Note: this property is only used for reference tokens
    /// and may be hashed or encrypted for security reasons.
    /// </remarks>
    public virtual string? ReferenceId { get; set; }

    /// <summary>
    /// Gets or sets the status of the token.
    /// </summary>
    public virtual string? Status { get; set; }

    /// <summary>
    /// Gets or sets the subject of the token.
    /// </summary>
    public virtual string? Subject { get; set; }

    /// <summary>
    /// Gets or sets the type of the token.
    /// </summary>
    public virtual string? Type { get; set; }
}
