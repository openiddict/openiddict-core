/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.WebIntegration;

/// <summary>
/// Provides various settings needed to configure the OpenIddict client Web providers.
/// </summary>
public abstract partial class OpenIddictClientWebIntegrationSettings
{
    /// <summary>
    /// Gets or sets the client identifier.
    /// </summary>
    public virtual string? ClientId { get; set; }

    /// <summary>
    /// Gets or sets the client secret, if applicable.
    /// </summary>
    public virtual string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets the redirection URL.
    /// </summary>
    public virtual Uri? RedirectUri { get; set; }

    /// <summary>
    /// Gets the scopes requested to the authorization server.
    /// </summary>
    public virtual HashSet<string> Scopes { get; } = new(StringComparer.Ordinal);
}
