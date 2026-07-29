using System.Security.Claims;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents an OpenIddict authorization descriptor.
/// </summary>
public class OpenIddictAuthorizationDescriptor
{
    /// <summary>
    /// Gets or sets the identifier of the application associated with the authorization.
    /// </summary>
    public string? ApplicationId { get; set; }

    /// <summary>
    /// Gets or sets the creation date of the authorization.
    /// </summary>
    public DateTimeOffset? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the optional principal specified by the caller.
    /// </summary>
    /// <remarks>
    /// Note: this property is not stored by the default stores.
    /// </remarks>
    public ClaimsPrincipal? Principal { get; set; }

    /// <summary>
    /// Gets or sets the additional properties of the authorization.
    /// </summary>
    public Dictionary<string, JsonElement> Properties { get; set; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets the scopes of the authorization.
    /// </summary>
    public HashSet<string> Scopes { get; set; } = [];

    /// <summary>
    /// Gets or sets the status of the authorization.
    /// </summary>
    public string? Status { get; set; }

    /// <summary>
    /// Gets or sets the subject of the authorization.
    /// </summary>
    public string? Subject { get; set; }

    /// <summary>
    /// Gets or sets the type of the authorization.
    /// </summary>
    public string? Type { get; set; }
}
