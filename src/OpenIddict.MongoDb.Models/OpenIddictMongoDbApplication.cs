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

namespace OpenIddict.MongoDb.Models;

/// <summary>
/// Represents an OpenIddict application.
/// </summary>
[DebuggerDisplay("Id = {Id.ToString(),nq} ; ClientId = {ClientId,nq} ; Type = {Type,nq}")]
public class OpenIddictMongoDbApplication
{
    /// <summary>
    /// Gets or sets the client identifier associated with the current application.
    /// </summary>
    [BsonElement("client_id"), BsonIgnoreIfNull]
    public virtual string? ClientId { get; set; }

    /// <summary>
    /// Gets or sets the client secret associated with the current application.
    /// Note: depending on the application manager used to create this instance,
    /// this property may be hashed or encrypted for security reasons.
    /// </summary>
    [BsonElement("client_secret"), BsonIgnoreIfNull]
    public virtual string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets the concurrency token.
    /// </summary>
    [BsonElement("concurrency_token"), BsonIgnoreIfNull]
    public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the consent type associated with the current application.
    /// </summary>
    [BsonElement("consent_type"), BsonIgnoreIfNull]
    public virtual string? ConsentType { get; set; }

    /// <summary>
    /// Gets or sets the display name associated with the current application.
    /// </summary>
    [BsonElement("display_name"), BsonIgnoreIfNull]
    public virtual string? DisplayName { get; set; }

    /// <summary>
    /// Gets or sets the localized display names associated with the current application.
    /// </summary>
    [BsonElement("display_names"), BsonIgnoreIfNull]
    public virtual IReadOnlyDictionary<CultureInfo, string> DisplayNames { get; set; }
        = ImmutableDictionary.Create<CultureInfo, string>();

    /// <summary>
    /// Gets or sets the unique identifier associated with the current application.
    /// </summary>
    [BsonId, BsonRequired]
    public virtual ObjectId Id { get; set; }

    /// <summary>
    /// Gets or sets the permissions associated with the current application.
    /// </summary>
    [BsonElement("permissions"), BsonIgnoreIfDefault]
    public virtual IReadOnlyList<string> Permissions { get; set; } = ImmutableList.Create<string>();

    /// <summary>
    /// Gets or sets the logout callback URLs associated with the current application.
    /// </summary>
    [BsonElement("post_logout_redirect_uris"), BsonIgnoreIfDefault]
    public virtual IReadOnlyList<string> PostLogoutRedirectUris { get; set; } = ImmutableList.Create<string>();

    /// <summary>
    /// Gets or sets the additional properties associated with the current application.
    /// </summary>
    [BsonElement("properties"), BsonIgnoreIfNull]
    public virtual BsonDocument? Properties { get; set; }

    /// <summary>
    /// Gets or sets the callback URLs associated with the current application.
    /// </summary>
    [BsonElement("redirect_uris"), BsonIgnoreIfDefault]
    public virtual IReadOnlyList<string> RedirectUris { get; set; } = ImmutableList.Create<string>();

    /// <summary>
    /// Gets or sets the requirements associated with the current application.
    /// </summary>
    [BsonElement("requirements"), BsonIgnoreIfDefault]
    public virtual IReadOnlyList<string> Requirements { get; set; } = ImmutableList.Create<string>();

    /// <summary>
    /// Gets or sets the application type
    /// associated with the current application.
    /// </summary>
    [BsonElement("type"), BsonIgnoreIfNull]
    public virtual string? Type { get; set; }
}
