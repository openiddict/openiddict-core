/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;

namespace OpenIddict.Client.WebIntegration;

/// <summary>
/// Represents an OpenIddict client web integration provider.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public class OpenIddictClientWebIntegrationProvider
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientWebIntegrationProvider"/> class.
    /// </summary>
    /// <param name="name">The provider name.</param>
    /// <param name="settings">The provider settings.</param>
    /// <exception cref="ArgumentException"><paramref name="name"/> is null or empty.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="settings"/> are null.</exception>
    public OpenIddictClientWebIntegrationProvider(
        string name,
        OpenIddictClientWebIntegrationSettings settings)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0330), nameof(name));
        }

        Name = name;
        Settings = settings ?? throw new ArgumentNullException(nameof(settings));
    }

    /// <summary>
    /// Gets the provider name associated with the current instance.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the provider settings associated with the current instance.
    /// </summary>
    public OpenIddictClientWebIntegrationSettings Settings { get; }
}
