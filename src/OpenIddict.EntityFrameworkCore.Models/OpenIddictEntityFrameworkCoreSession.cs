/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Text.Json;

namespace OpenIddict.EntityFrameworkCore.Models;

/// <summary>
/// Represents an OpenIddict session.
/// </summary>
public class OpenIddictEntityFrameworkCoreSession :
    OpenIddictEntityFrameworkCoreSession<string,
                                         OpenIddictEntityFrameworkCoreApplication,
                                         OpenIddictEntityFrameworkCoreAuthorization>
{
    public OpenIddictEntityFrameworkCoreSession() => Id = Guid.NewGuid().ToString();
}

/// <summary>
/// Represents an OpenIddict session.
/// </summary>
public class OpenIddictEntityFrameworkCoreSession<TKey> :
    OpenIddictEntityFrameworkCoreSession<TKey,
                                         OpenIddictEntityFrameworkCoreApplication<TKey>,
                                         OpenIddictEntityFrameworkCoreAuthorization<TKey>>
    where TKey : notnull, IEquatable<TKey>;

/// <summary>
/// Represents an OpenIddict session.
/// </summary>
[DebuggerDisplay("Id = {Id.ToString(),nq} ; Subject = {Subject,nq} ; LoginId = {LoginId,nq} ; Status = {Status,nq}")]
public class OpenIddictEntityFrameworkCoreSession<TKey, TApplication, TAuthorization>
    where TKey : notnull, IEquatable<TKey>
    where TApplication : class
    where TAuthorization : class
{
    /// <summary>
    /// Gets or sets the application associated with the session.
    /// </summary>
    public virtual TApplication? Application { get; set; }

    /// <summary>
    /// Gets or sets the authorization associated with the session.
    /// </summary>
    public virtual TAuthorization? Authorization { get; set; }

    /// <summary>
    /// Gets or sets the concurrency token of the session.
    /// </summary>
    public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the UTC creation date of the session.
    /// </summary>
    public virtual DateTime? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the session.
    /// </summary>
    public virtual TKey? Id { get; set; }

    /// <summary>
    /// Gets or sets the login identifier of the session.
    /// </summary>
    public virtual string? LoginId { get; set; }

    /// <summary>
    /// Gets or sets the additional properties of the session.
    /// </summary>
    public virtual IDictionary<string, JsonElement>? Properties { get; set; }

    /// <summary>
    /// Gets or sets the status of the session.
    /// </summary>
    public virtual string? Status { get; set; }

    /// <summary>
    /// Gets or sets the subject of the session.
    /// </summary>
    public virtual string? Subject { get; set; }
}
