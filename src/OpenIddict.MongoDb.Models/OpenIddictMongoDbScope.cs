/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;

namespace OpenIddict.MongoDb.Models;

/// <summary>
/// Represents an OpenIddict scope.
/// </summary>
[DebuggerDisplay("Id = {Id.ToString(),nq} ; Name = {Name,nq}")]
public class OpenIddictMongoDbScope
{
    /// <summary>
    /// Gets or sets the concurrency token of the scope.
    /// </summary>
    [BsonElement("concurrency_token"), BsonIgnoreIfNull]
    public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the public description of the scope.
    /// </summary>
    [BsonElement("description"), BsonIgnoreIfNull]
    public virtual string? Description { get; set; }

    /// <summary>
    /// Gets or sets the localized public descriptions of the scope.
    /// </summary>
    [BsonElement("descriptions"), BsonIgnoreIfNull]
    public virtual ImmutableDictionary<string, string>? Descriptions { get; set; }

    /// <summary>
    /// Gets or sets the display name of the scope.
    /// </summary>
    [BsonElement("display_name"), BsonIgnoreIfNull]
    public virtual string? DisplayName { get; set; }

    /// <summary>
    /// Gets or sets the localized display names of the scope.
    /// </summary>
    [BsonElement("display_names"), BsonIgnoreIfNull]
    public virtual ImmutableDictionary<string, string>? DisplayNames { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the scope.
    /// </summary>
    [BsonId, BsonRequired]
    public virtual ObjectId Id { get; set; }

    /// <summary>
    /// Gets or sets the unique name of the scope.
    /// </summary>
    [BsonElement("name"), BsonIgnoreIfNull]
    public virtual string? Name { get; set; }

    /// <summary>
    /// Gets or sets the additional properties of the scope.
    /// </summary>
    [BsonElement("properties"), BsonIgnoreIfNull]
    public virtual BsonDocument? Properties { get; set; }

    /// <summary>
    /// Gets or sets the resources associated with the scope.
    /// </summary>
    [BsonElement("resources"), BsonIgnoreIfNull]
    public virtual ImmutableArray<string>? Resources { get; set; }
}
