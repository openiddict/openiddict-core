/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;

namespace OpenIddict.MongoDb.Models;

/// <summary>
/// Represents an OpenIddict cryptographic key.
/// </summary>
[DebuggerDisplay("Id = {Id.ToString(),nq} ; KeyId = {KeyId,nq} ; Usage = {Usage,nq} ; Status = {Status,nq}")]
public class OpenIddictMongoDbKey
{
    /// <summary>
    /// Gets or sets the UTC date from which the key is used to protect new tokens.
    /// </summary>
    [BsonElement("activation_date"), BsonIgnoreIfNull]
    public virtual DateTime? ActivationDate { get; set; }

    /// <summary>
    /// Gets or sets the JSON Web Algorithm associated with the key.
    /// </summary>
    [BsonElement("algorithm"), BsonIgnoreIfNull]
    public virtual string? Algorithm { get; set; }

    /// <summary>
    /// Gets or sets the concurrency token of the key.
    /// </summary>
    [BsonElement("concurrency_token"), BsonIgnoreIfNull]
    public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the UTC creation date of the key.
    /// </summary>
    [BsonElement("creation_date"), BsonIgnoreIfNull]
    public virtual DateTime? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the UTC date after which the key is no longer used to protect new tokens.
    /// </summary>
    [BsonElement("expiration_date"), BsonIgnoreIfNull]
    public virtual DateTime? ExpirationDate { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the key.
    /// </summary>
    [BsonId, BsonRequired]
    public virtual ObjectId Id { get; set; }

    /// <summary>
    /// Gets or sets the public key identifier ("kid") of the key.
    /// </summary>
    [BsonElement("key_id"), BsonIgnoreIfNull]
    public virtual string? KeyId { get; set; }

    /// <summary>
    /// Gets or sets the protected key material.
    /// </summary>
    [BsonElement("payload"), BsonIgnoreIfNull]
    public virtual string? Payload { get; set; }

    /// <summary>
    /// Gets or sets the additional properties of the key.
    /// </summary>
    [BsonElement("properties"), BsonIgnoreIfNull]
    public virtual BsonDocument? Properties { get; set; }

    /// <summary>
    /// Gets or sets the UTC date after which the key is no longer used to unprotect tokens.
    /// </summary>
    [BsonElement("retirement_date"), BsonIgnoreIfNull]
    public virtual DateTime? RetirementDate { get; set; }

    /// <summary>
    /// Gets or sets the status of the key.
    /// </summary>
    [BsonElement("status"), BsonIgnoreIfNull]
    public virtual string? Status { get; set; }

    /// <summary>
    /// Gets or sets the usage of the key ("sig" or "enc").
    /// </summary>
    [BsonElement("usage"), BsonIgnoreIfNull]
    public virtual string? Usage { get; set; }
}
