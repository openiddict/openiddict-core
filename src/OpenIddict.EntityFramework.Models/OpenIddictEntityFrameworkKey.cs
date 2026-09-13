/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;

namespace OpenIddict.EntityFramework.Models;

/// <summary>
/// Represents an OpenIddict cryptographic key.
/// </summary>
public class OpenIddictEntityFrameworkKey : OpenIddictEntityFrameworkKey<string>
{
    public OpenIddictEntityFrameworkKey() => Id = Guid.NewGuid().ToString();
}

/// <summary>
/// Represents an OpenIddict cryptographic key.
/// </summary>
[DebuggerDisplay("Id = {Id.ToString(),nq} ; KeyId = {KeyId,nq} ; Usage = {Usage,nq} ; Status = {Status,nq}")]
public class OpenIddictEntityFrameworkKey<TKey> where TKey : notnull, IEquatable<TKey>
{
    /// <summary>
    /// Gets or sets the UTC date from which the key is used to protect new tokens.
    /// </summary>
    public virtual DateTime? ActivationDate { get; set; }

    /// <summary>
    /// Gets or sets the JSON Web Algorithm associated with the key.
    /// </summary>
    public virtual string? Algorithm { get; set; }

    /// <summary>
    /// Gets or sets the concurrency token of the key.
    /// </summary>
    public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the UTC creation date of the key.
    /// </summary>
    public virtual DateTime? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the UTC date after which the key is no longer used to protect new tokens.
    /// </summary>
    public virtual DateTime? ExpirationDate { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the key.
    /// </summary>
    public virtual TKey? Id { get; set; }

    /// <summary>
    /// Gets or sets the public key identifier ("kid") of the key.
    /// </summary>
    public virtual string? KeyId { get; set; }

    /// <summary>
    /// Gets or sets the protected key material.
    /// </summary>
    public virtual string? Payload { get; set; }

    /// <summary>
    /// Gets or sets the additional properties serialized as a JSON object, or <see langword="null"/> if no bag was associated with the current key.
    /// </summary>
    public virtual string? Properties { get; set; }

    /// <summary>
    /// Gets or sets the UTC date after which the key is no longer used to unprotect tokens.
    /// </summary>
    public virtual DateTime? RetirementDate { get; set; }

    /// <summary>
    /// Gets or sets the status of the key.
    /// </summary>
    public virtual string? Status { get; set; }

    /// <summary>
    /// Gets or sets the usage of the key ("sig" or "enc").
    /// </summary>
    public virtual string? Usage { get; set; }
}
