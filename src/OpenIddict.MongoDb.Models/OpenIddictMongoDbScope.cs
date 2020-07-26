/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace OpenIddict.MongoDb.Models
{
    /// <summary>
    /// Represents an OpenIddict scope.
    /// </summary>
    [DebuggerDisplay("Id = {Id.ToString(),nq} ; Name = {Name,nq}")]
    public class OpenIddictMongoDbScope
    {
        /// <summary>
        /// Gets or sets the concurrency token.
        /// </summary>
        [BsonElement("concurrency_token"), BsonIgnoreIfNull]
        public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Gets or sets the public description associated with the current scope.
        /// </summary>
        [BsonElement("description"), BsonIgnoreIfNull]
        public virtual string? Description { get; set; }

        /// <summary>
        /// Gets or sets the localized public descriptions associated with the current scope.
        /// </summary>
        [BsonElement("descriptions"), BsonIgnoreIfNull]
        public virtual IReadOnlyDictionary<CultureInfo, string> Descriptions { get; set; }
            = ImmutableDictionary.Create<CultureInfo, string>();

        /// <summary>
        /// Gets or sets the display name associated with the current scope.
        /// </summary>
        [BsonElement("display_name"), BsonIgnoreIfNull]
        public virtual string? DisplayName { get; set; }

        /// <summary>
        /// Gets or sets the localized display names associated with the current scope.
        /// </summary>
        [BsonElement("display_names"), BsonIgnoreIfNull]
        public virtual IReadOnlyDictionary<CultureInfo, string> DisplayNames { get; set; }
            = ImmutableDictionary.Create<CultureInfo, string>();

        /// <summary>
        /// Gets or sets the unique identifier associated with the current scope.
        /// </summary>
        [BsonId, BsonRequired]
        public virtual ObjectId Id { get; set; }

        /// <summary>
        /// Gets or sets the unique name associated with the current scope.
        /// </summary>
        [BsonElement("name"), BsonIgnoreIfNull]
        public virtual string? Name { get; set; }

        /// <summary>
        /// Gets or sets the additional properties associated with the current scope.
        /// </summary>
        [BsonElement("properties"), BsonIgnoreIfNull]
        public virtual BsonDocument? Properties { get; set; }

        /// <summary>
        /// Gets or sets the resources associated with the current scope.
        /// </summary>
        [BsonElement("resources"), BsonIgnoreIfDefault]
        public virtual IReadOnlyList<string> Resources { get; set; } = ImmutableArray.Create<string>();
    }
}
