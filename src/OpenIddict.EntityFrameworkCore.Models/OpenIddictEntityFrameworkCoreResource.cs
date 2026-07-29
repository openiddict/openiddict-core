/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Text.Json;

namespace OpenIddict.EntityFrameworkCore.Models;

/// <summary>
/// Represents an OpenIddict resource.
/// </summary>
public class OpenIddictEntityFrameworkCoreResource :
    OpenIddictEntityFrameworkCoreResource<string>
{
    public OpenIddictEntityFrameworkCoreResource() => Id = Guid.NewGuid().ToString();
}

/// <summary>
/// Represents an OpenIddict resource.
/// </summary>
[DebuggerDisplay("Id = {Id.ToString(),nq} ; Name = {Name,nq}")]
public class OpenIddictEntityFrameworkCoreResource<TKey> where TKey : notnull, IEquatable<TKey>
{
    /// <summary>
    /// Gets or sets the concurrency token of the resource.
    /// </summary>
    public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the public description of the resource.
    /// </summary>
    public virtual string? Description { get; set; }

    /// <summary>
    /// Gets or sets the localized public descriptions of the resource.
    /// </summary>
    public virtual IDictionary<string, string>? Descriptions { get; set; }

    /// <summary>
    /// Gets or sets the display name of the resource.
    /// </summary>
    public virtual string? DisplayName { get; set; }

    /// <summary>
    /// Gets or sets the localized display names of the resource.
    /// </summary>
    public virtual IDictionary<string, string>? DisplayNames { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the resource.
    /// </summary>
    public virtual TKey? Id { get; set; }

    /// <summary>
    /// Gets or sets the unique name of the resource.
    /// </summary>
    public virtual string? Name { get; set; }

    /// <summary>
    /// Gets or sets the additional properties of the resource.
    /// </summary>
    public virtual IDictionary<string, JsonElement>? Properties { get; set; }
}
