/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.WebIntegration;

/// <summary>
/// Provides various settings needed to configure the OpenIddict client Web integration.
/// </summary>
public class OpenIddictClientWebIntegrationOptions
{
    /// <summary>
    /// Gets the list of provider integrations enabled for this application.
    /// </summary>
    public List<OpenIddictClientWebIntegrationProvider> Providers { get; } = new();
}
