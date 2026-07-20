using System.Globalization;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents an OpenIddict resource descriptor.
/// </summary>
public class OpenIddictResourceDescriptor
{
    /// <summary>
    /// Gets or sets the description associated with the resource.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Gets the localized descriptions associated with the resource.
    /// </summary>
    public Dictionary<CultureInfo, string> Descriptions { get; } = [];

    /// <summary>
    /// Gets or sets the display name associated with the resource.
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Gets the localized display names associated with the resource.
    /// </summary>
    public Dictionary<CultureInfo, string> DisplayNames { get; } = [];

    /// <summary>
    /// Gets or sets the unique name associated with the resource.
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// Gets the additional properties associated with the resource.
    /// </summary>
    public Dictionary<string, JsonElement> Properties { get; } = new(StringComparer.Ordinal);
}
