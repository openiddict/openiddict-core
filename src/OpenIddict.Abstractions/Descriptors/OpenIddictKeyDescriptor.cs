using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents an OpenIddict key descriptor.
/// </summary>
public class OpenIddictKeyDescriptor
{
    /// <summary>
    /// Gets or sets the date from which the key is used to protect new tokens.
    /// </summary>
    public DateTimeOffset? ActivationDate { get; set; }

    /// <summary>
    /// Gets or sets the JSON Web Algorithm associated with the key.
    /// </summary>
    public string? Algorithm { get; set; }

    /// <summary>
    /// Gets or sets the creation date of the key.
    /// </summary>
    public DateTimeOffset? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the date after which the key is no longer used to protect new tokens.
    /// </summary>
    public DateTimeOffset? ExpirationDate { get; set; }

    /// <summary>
    /// Gets or sets the public key identifier ("kid") of the key.
    /// </summary>
    public string? KeyId { get; set; }

    /// <summary>
    /// Gets or sets the protected key material.
    /// </summary>
    public string? Payload { get; set; }

    /// <summary>
    /// Gets the additional properties of the key.
    /// </summary>
    public Dictionary<string, JsonElement> Properties { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets the date after which the key is no longer used to unprotect tokens.
    /// </summary>
    public DateTimeOffset? RetirementDate { get; set; }

    /// <summary>
    /// Gets or sets the status of the key.
    /// </summary>
    public string? Status { get; set; }

    /// <summary>
    /// Gets or sets the usage of the key ("sig" or "enc").
    /// </summary>
    public string? Usage { get; set; }
}
