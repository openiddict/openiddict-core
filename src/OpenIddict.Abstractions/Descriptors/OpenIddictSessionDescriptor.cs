using System.Security.Claims;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents an OpenIddict session descriptor.
/// </summary>
public class OpenIddictSessionDescriptor
{
    /// <summary>
    /// Gets or sets the identifier of the application associated with the session.
    /// </summary>
    public string? ApplicationId { get; set; }

    /// <summary>
    /// Gets or sets the identifier of the authorization associated with the session.
    /// </summary>
    public string? AuthorizationId { get; set; }

    /// <summary>
    /// Gets or sets the creation date of the session.
    /// </summary>
    public DateTimeOffset? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the login identifier of the session.
    /// </summary>
    public string? LoginId { get; set; }

    /// <summary>
    /// Gets or sets the optional principal specified by the caller.
    /// </summary>
    /// <remarks>
    /// Note: this property is not stored by the default stores.
    /// </remarks>
    public ClaimsPrincipal? Principal { get; set; }

    /// <summary>
    /// Gets the additional properties of the session.
    /// </summary>
    public Dictionary<string, JsonElement> Properties { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets the status of the session.
    /// </summary>
    public string? Status { get; set; }

    /// <summary>
    /// Gets or sets the subject of the session.
    /// </summary>
    public string? Subject { get; set; }
}
