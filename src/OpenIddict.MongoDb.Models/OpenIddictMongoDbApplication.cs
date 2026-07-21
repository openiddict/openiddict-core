/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;

namespace OpenIddict.MongoDb.Models;

/// <summary>
/// Represents an OpenIddict application.
/// </summary>
[DebuggerDisplay("Id = {Id.ToString(),nq} ; ClientId = {ClientId,nq} ; ClientType = {ClientType,nq}")]
public class OpenIddictMongoDbApplication
{
    /// <summary>
    /// Gets or sets the application type of the application.
    /// </summary>
    [BsonElement("application_type"), BsonIgnoreIfNull]
    public virtual string? ApplicationType { get; set; }

    /// <summary>
    /// Gets or sets the client identifier of the application.
    /// </summary>
    [BsonElement("client_id"), BsonIgnoreIfNull]
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
    [BsonElement("client_secret"), BsonIgnoreIfNull]
    public virtual string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets the client type of the application.
    /// </summary>
    [BsonElement("client_type"), BsonIgnoreIfNull]
    public virtual string? ClientType { get; set; }

    /// <summary>
    /// Gets or sets the concurrency token of the application.
    /// </summary>
    [BsonElement("concurrency_token"), BsonIgnoreIfNull]
    public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the consent type of the application.
    /// </summary>
    [BsonElement("consent_type"), BsonIgnoreIfNull]
    public virtual string? ConsentType { get; set; }

    /// <summary>
    /// Gets or sets the display name of the application.
    /// </summary>
    [BsonElement("display_name"), BsonIgnoreIfNull]
    public virtual string? DisplayName { get; set; }

    /// <summary>
    /// Gets or sets the localized display names of the application.
    /// </summary>
    [BsonElement("display_names"), BsonIgnoreIfNull]
    public virtual ImmutableDictionary<string, string>? DisplayNames { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the application.
    /// </summary>
    [BsonId, BsonRequired]
    public virtual ObjectId Id { get; set; }

    /// <summary>
    /// Gets or sets the JSON Web Key Set of the application.
    /// </summary>
    [BsonElement("json_web_key_set"), BsonIgnoreIfNull]
    public virtual BsonDocument? JsonWebKeySet { get; set; }

    /// <summary>
    /// Gets or sets the permissions of the application.
    /// </summary>
    [BsonElement("permissions"), BsonIgnoreIfNull]
    public virtual ImmutableArray<string>? Permissions { get; set; }

    /// <summary>
    /// Gets or sets the post-logout redirect URIs of the application.
    /// </summary>
    [BsonElement("post_logout_redirect_uris"), BsonIgnoreIfNull]
    public virtual ImmutableArray<string>? PostLogoutRedirectUris { get; set; }

    /// <summary>
    /// Gets or sets the additional properties of the application.
    /// </summary>
    [BsonElement("properties"), BsonIgnoreIfNull]
    public virtual BsonDocument? Properties { get; set; }

    /// <summary>
    /// Gets or sets the redirect URIs of the application.
    /// </summary>
    [BsonElement("redirect_uris"), BsonIgnoreIfNull]
    public virtual ImmutableArray<string>? RedirectUris { get; set; }

    /// <summary>
    /// Gets or sets the requirements of the application.
    /// </summary>
    [BsonElement("requirements"), BsonIgnoreIfNull]
    public virtual ImmutableArray<string>? Requirements { get; set; }

    /// <summary>
    /// Gets or sets the settings of the application.
    /// </summary>
    [BsonElement("settings"), BsonIgnoreIfNull]
    public virtual ImmutableDictionary<string, string>? Settings { get; set; }
}
