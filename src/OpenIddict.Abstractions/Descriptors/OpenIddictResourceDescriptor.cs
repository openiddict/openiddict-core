using System.Globalization;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents an OpenIddict resource descriptor.
/// </summary>
public class OpenIddictResourceDescriptor
{
    /// <summary>
    /// Gets or sets the description of the resource.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Gets the localized descriptions of the resource.
    /// </summary>
    public Dictionary<CultureInfo, string> Descriptions { get; } = [];

    /// <summary>
    /// Gets or sets the display name of the resource.
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Gets the localized display names of the resource.
    /// </summary>
    public Dictionary<CultureInfo, string> DisplayNames { get; } = [];

    /// <summary>
    /// Gets or sets the unique name of the resource.
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// Gets the additional properties of the resource.
    /// </summary>
    public Dictionary<string, JsonElement> Properties { get; } = new(StringComparer.Ordinal);
}
