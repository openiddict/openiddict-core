/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;

namespace OpenIddict.MongoDb.Models;

/// <summary>
/// Represents an OpenIddict session.
/// </summary>
[DebuggerDisplay("Id = {Id.ToString(),nq} ; Subject = {Subject,nq} ; LoginId = {LoginId,nq} ; Status = {Status,nq}")]
public class OpenIddictMongoDbSession
{
    /// <summary>
    /// Gets or sets the identifier of the application associated with the session.
    /// </summary>
    [BsonElement("application_id"), BsonIgnoreIfDefault]
    public virtual ObjectId ApplicationId { get; set; }

    /// <summary>
    /// Gets or sets the identifier of the authorization associated with the session.
    /// </summary>
    [BsonElement("authorization_id"), BsonIgnoreIfDefault]
    public virtual ObjectId AuthorizationId { get; set; }

    /// <summary>
    /// Gets or sets the concurrency token of the session.
    /// </summary>
    [BsonElement("concurrency_token"), BsonIgnoreIfNull]
    public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the UTC creation date of the session.
    /// </summary>
    [BsonElement("creation_date"), BsonIgnoreIfNull]
    public virtual DateTime? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the session.
    /// </summary>
    [BsonId, BsonRequired]
    public virtual ObjectId Id { get; set; }

    /// <summary>
    /// Gets or sets the login identifier of the session.
    /// </summary>
    [BsonElement("login_id"), BsonIgnoreIfNull]
    public virtual string? LoginId { get; set; }

    /// <summary>
    /// Gets or sets the additional properties of the session.
    /// </summary>
    [BsonElement("properties"), BsonIgnoreIfNull]
    public virtual BsonDocument? Properties { get; set; }

    /// <summary>
    /// Gets or sets the status of the session.
    /// </summary>
    [BsonElement("status"), BsonIgnoreIfNull]
    public virtual string? Status { get; set; }

    /// <summary>
    /// Gets or sets the subject of the session.
    /// </summary>
    [BsonElement("subject"), BsonIgnoreIfNull]
    public virtual string? Subject { get; set; }
}
