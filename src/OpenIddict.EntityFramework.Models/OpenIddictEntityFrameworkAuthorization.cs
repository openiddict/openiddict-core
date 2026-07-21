/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace OpenIddict.EntityFramework.Models;

/// <summary>
/// Represents an OpenIddict authorization.
/// </summary>
public class OpenIddictEntityFrameworkAuthorization : OpenIddictEntityFrameworkAuthorization<string, OpenIddictEntityFrameworkApplication, OpenIddictEntityFrameworkToken>
{
    public OpenIddictEntityFrameworkAuthorization() => Id = Guid.NewGuid().ToString();
}

/// <summary>
/// Represents an OpenIddict authorization.
/// </summary>
[DebuggerDisplay("Id = {Id.ToString(),nq} ; Subject = {Subject,nq} ; Type = {Type,nq} ; Status = {Status,nq}")]
public class OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TToken>
    where TKey : notnull, IEquatable<TKey>
    where TApplication : class
    where TToken : class
{
    /// <summary>
    /// Gets or sets the application associated with the authorization.
    /// </summary>
    public virtual TApplication? Application { get; set; }

    /// <summary>
    /// Gets or sets the concurrency token of the authorization.
    /// </summary>
    public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the UTC creation date of the authorization.
    /// </summary>
    public virtual DateTime? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the authorization.
    /// </summary>
    public virtual TKey? Id { get; set; }

    /// <summary>
    /// Gets or sets the additional properties of the authorization, serialized as a JSON object.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Json)]
    public virtual string? Properties { get; set; }

    /// <summary>
    /// Gets or sets the scopes of the authorization, serialized as a JSON array.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Json)]
    public virtual string? Scopes { get; set; }

    /// <summary>
    /// Gets or sets the status of the authorization.
    /// </summary>
    public virtual string? Status { get; set; }

    /// <summary>
    /// Gets or sets the subject of the authorization.
    /// </summary>
    public virtual string? Subject { get; set; }

    /// <summary>
    /// Gets the list of tokens associated with the authorization.
    /// </summary>
    public virtual ICollection<TToken> Tokens { get; } = new HashSet<TToken>();

    /// <summary>
    /// Gets or sets the type of the authorization.
    /// </summary>
    public virtual string? Type { get; set; }
}
