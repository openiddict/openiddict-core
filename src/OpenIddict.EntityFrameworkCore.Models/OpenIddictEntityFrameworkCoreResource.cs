/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace OpenIddict.EntityFrameworkCore.Models;

/// <summary>
/// Represents an OpenIddict resource.
/// </summary>
public class OpenIddictEntityFrameworkCoreResource : OpenIddictEntityFrameworkCoreResource<string>
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
    /// Gets or sets the concurrency token.
    /// </summary>
    public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the public description associated with the current resource.
    /// </summary>
    public virtual string? Description { get; set; }

    /// <summary>
    /// Gets or sets the localized public descriptions associated
    /// with the current resource, serialized as a JSON object.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Json)]
    public virtual string? Descriptions { get; set; }

    /// <summary>
    /// Gets or sets the display name associated with the current resource.
    /// </summary>
    public virtual string? DisplayName { get; set; }

    /// <summary>
    /// Gets or sets the localized display names
    /// associated with the current application,
    /// serialized as a JSON object.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Json)]
    public virtual string? DisplayNames { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier associated with the current resource.
    /// </summary>
    public virtual TKey? Id { get; set; }

    /// <summary>
    /// Gets or sets the unique name associated with the current resource.
    /// </summary>
    public virtual string? Name { get; set; }

    /// <summary>
    /// Gets or sets the additional properties serialized as a JSON object,
    /// or <see langword="null"/> if no bag was associated with the current resource.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Json)]
    public virtual string? Properties { get; set; }
}
