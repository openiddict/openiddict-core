using System.Globalization;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents an OpenIddict scope descriptor.
/// </summary>
public class OpenIddictScopeDescriptor
{
    /// <summary>
    /// Gets or sets the description of the scope.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Gets the localized descriptions of the scope.
    /// </summary>
    public Dictionary<CultureInfo, string> Descriptions { get; } = [];

    /// <summary>
    /// Gets or sets the display name of the scope.
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Gets the localized display names of the scope.
    /// </summary>
    public Dictionary<CultureInfo, string> DisplayNames { get; } = [];

    /// <summary>
    /// Gets or sets the unique name of the scope.
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// Gets the additional properties of the scope.
    /// </summary>
    public Dictionary<string, JsonElement> Properties { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the resources of the scope.
    /// </summary>
    public HashSet<string> Resources { get; } = new(StringComparer.Ordinal);
}
