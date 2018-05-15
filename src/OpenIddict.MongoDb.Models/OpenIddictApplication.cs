/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace OpenIddict.MongoDb.Models
{
    /// <summary>
    /// Represents an OpenIddict application.
    /// </summary>
    public class OpenIddictApplication
    {
        /// <summary>
        /// Gets or sets the client identifier
        /// associated with the current application.
        /// </summary>
        [BsonElement("client_id"), BsonRequired]
        public virtual string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client secret associated with the current application.
        /// Note: depending on the application manager used to create this instance,
        /// this property may be hashed or encrypted for security reasons.
        /// </summary>
        [BsonElement("client_secret"), BsonIgnoreIfNull]
        public virtual string ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the concurrency token.
        /// </summary>
        [BsonElement("concurrency_token"), BsonRequired]
        public virtual string ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Gets or sets the consent type
        /// associated with the current application.
        /// </summary>
        [BsonElement("consent_type"), BsonIgnoreIfNull]
        public virtual string ConsentType { get; set; }

        /// <summary>
        /// Gets or sets the display name
        /// associated with the current application.
        /// </summary>
        [BsonElement("display_name"), BsonIgnoreIfNull]
        public virtual string DisplayName { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier
        /// associated with the current application.
        /// </summary>
        [BsonId, BsonRequired]
        public virtual ObjectId Id { get; set; }

        /// <summary>
        /// Gets or sets the permissions associated with the current application.
        /// </summary>
        [BsonElement("permissions"), BsonIgnoreIfDefault]
        public virtual string[] Permissions { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Gets or sets the logout callback URLs associated with the current application.
        /// </summary>
        [BsonElement("post_logout_redirect_uris"), BsonIgnoreIfDefault]
        public virtual string[] PostLogoutRedirectUris { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Gets or sets the additional properties associated with the current application.
        /// </summary>
        [BsonExtraElements]
        public virtual BsonDocument Properties { get; set; } = new BsonDocument();

        /// <summary>
        /// Gets or sets the callback URLs associated with the current application.
        /// </summary>
        [BsonElement("redirect_uris"), BsonIgnoreIfDefault]
        public virtual string[] RedirectUris { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Gets or sets the application type
        /// associated with the current application.
        /// </summary>
        [BsonElement("type"), BsonRequired]
        public virtual string Type { get; set; }
    }
}