using System.Security.Claims;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents an OpenIddict token descriptor.
/// </summary>
public class OpenIddictTokenDescriptor
{
    /// <summary>
    /// Gets or sets the identifier of the application associated with the token.
    /// </summary>
    public string? ApplicationId { get; set; }

    /// <summary>
    /// Gets or sets the identifier of the authorization associated with the token.
    /// </summary>
    public string? AuthorizationId { get; set; }

    /// <summary>
    /// Gets or sets the creation date of the token.
    /// </summary>
    public DateTimeOffset? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the expiration date of the token.
    /// </summary>
    public DateTimeOffset? ExpirationDate { get; set; }

    /// <summary>
    /// Gets or sets the payload of the token.
    /// </summary>
    public string? Payload { get; set; }

    /// <summary>
    /// Gets or sets the optional principal specified by the caller.
    /// </summary>
    /// <remarks>
    /// Note: this property is not stored by the default stores.
    /// </remarks>
    public ClaimsPrincipal? Principal { get; set; }

    /// <summary>
    /// Gets the additional properties of the token.
    /// </summary>
    public Dictionary<string, JsonElement> Properties { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets the redemption date of the token.
    /// </summary>
    public DateTimeOffset? RedemptionDate { get; set; }

    /// <summary>
    /// Gets or sets the reference identifier of the token.
    /// </summary>
    /// <remarks>
    /// Note: depending on the application manager used when creating it,
    /// this property may be hashed or encrypted for security reasons.
    /// </remarks>
    public string? ReferenceId { get; set; }

    /// <summary>
    /// Gets or sets the identifier of the session associated with the token.
    /// </summary>
    public string? SessionId { get; set; }

    /// <summary>
    /// Gets or sets the status of the token.
    /// </summary>
    public string? Status { get; set; }

    /// <summary>
    /// Gets or sets the subject of the token.
    /// </summary>
    public string? Subject { get; set; }

    /// <summary>
    /// Gets or sets the type of the token.
    /// </summary>
    public string? Type { get; set; }
}
