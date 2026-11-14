using System.ComponentModel;
using System.Globalization;

namespace OpenIddict.Abstractions;

/// <summary>
/// Exposes the resource strings commonly used by the OpenIddict projects.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictResources
{
    /// <summary>
    /// Gets or sets the culture used to retrieve localized resources.
    /// </summary>
    public static CultureInfo? Culture { get; set; }

    /// <summary>
    /// Gets the resource string for the specified key.
    /// </summary>
    /// <param name="resourceKey">The key of the resource string to retrieve.</param>
    /// <param name="defaultValue">The value to return if the resource string is not found.</param>
    /// <returns>The resource string for the specified key, or <paramref name="defaultValue"/> if it is not found.</returns>
    public static string GetResourceString(string resourceKey, string defaultValue = null!) =>
        ResourceManager.GetString(resourceKey, Culture) ?? defaultValue;

    /// <summary>
    /// Gets a resource string with named format placeholders replaced by indexed placeholders.
    /// </summary>
    /// <param name="resourceKey">The key of the resource string to retrieve.</param>
    /// <param name="formatterNames">The names of the format placeholders to replace, in order.</param>
    /// <returns>The resource string with the named placeholders replaced by indexed placeholders.</returns>
    private static string GetResourceString(string resourceKey, string[] formatterNames)
    {
        var value = GetResourceString(resourceKey);
        for (var index = 0; index < formatterNames.Length; index++)
        {
            value = value.Replace("{" + formatterNames[index] + "}", "{" + index.ToString(CultureInfo.InvariantCulture) + "}", StringComparison.OrdinalIgnoreCase);
        }

        return value;
    }
}
