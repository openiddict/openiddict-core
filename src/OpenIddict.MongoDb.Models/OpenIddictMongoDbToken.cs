/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;

namespace OpenIddict.MongoDb.Models;

/// <summary>
/// Represents an OpenIddict token.
/// </summary>
[DebuggerDisplay("Id = {Id.ToString(),nq} ; Subject = {Subject,nq} ; Type = {Type,nq} ; Status = {Status,nq}")]
public class OpenIddictMongoDbToken
{
    /// <summary>
    /// Gets or sets the identifier of the application associated with the token.
    /// </summary>
    [BsonElement("application_id"), BsonIgnoreIfDefault]
    public virtual ObjectId ApplicationId { get; set; }

    /// <summary>
    /// Gets or sets the identifier of the authorization associated with the token.
    /// </summary>
    [BsonElement("authorization_id"), BsonIgnoreIfDefault]
    public virtual ObjectId AuthorizationId { get; set; }

    /// <summary>
    /// Gets or sets the concurrency token of the token.
    /// </summary>
    [BsonElement("concurrency_token"), BsonIgnoreIfNull]
    public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the UTC creation date of the token.
    /// </summary>
    [BsonElement("creation_date"), BsonIgnoreIfNull]
    public virtual DateTime? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the UTC expiration date of the token.
    /// </summary>
    [BsonElement("expiration_date"), BsonIgnoreIfNull]
    public virtual DateTime? ExpirationDate { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the token.
    /// </summary>
    [BsonId, BsonRequired]
    public virtual ObjectId Id { get; set; }

    /// <summary>
    /// Gets or sets the payload of the token.
    /// </summary>
    /// <remarks>
    /// Note: this property is only used for reference tokens
    /// and may be hashed or encrypted for security reasons.
    /// </remarks>
    [BsonElement("payload"), BsonIgnoreIfNull]
    public virtual string? Payload { get; set; }

    /// <summary>
    /// Gets or sets the additional properties associated with the token.
    /// </summary>
    [BsonElement("properties"), BsonIgnoreIfNull]
    public virtual BsonDocument? Properties { get; set; }

    /// <summary>
    /// Gets or sets the UTC redemption date of the token.
    /// </summary>
    [BsonElement("redemption_date"), BsonIgnoreIfNull]
    public virtual DateTime? RedemptionDate { get; set; }

    /// <summary>
    /// Gets or sets the reference identifier associated with the token.
    /// </summary>
    /// <remarks>
    /// Note: this property is only used for reference tokens
    /// and may be hashed or encrypted for security reasons.
    /// </remarks>
    [BsonElement("reference_id"), BsonIgnoreIfNull]
    public virtual string? ReferenceId { get; set; }

    /// <summary>
    /// Gets or sets the status of the token.
    /// </summary>
    [BsonElement("status"), BsonIgnoreIfNull]
    public virtual string? Status { get; set; }

    /// <summary>
    /// Gets or sets the subject associated with the token.
    /// </summary>
    [BsonElement("subject"), BsonIgnoreIfNull]
    public virtual string? Subject { get; set; }

    /// <summary>
    /// Gets or sets the type of the token.
    /// </summary>
    [BsonElement("type"), BsonIgnoreIfNull]
    public virtual string? Type { get; set; }
}
