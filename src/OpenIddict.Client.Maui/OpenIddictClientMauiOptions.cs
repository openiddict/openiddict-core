/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.Maui;

/// <summary>
/// Provides various settings needed to configure the OpenIddict MAUI client integration.
/// </summary>
public class OpenIddictClientMauiOptions
{
    /// <summary>
    /// Gets or sets the timeout after which authentication demands
    /// that are not completed are automatically aborted by OpenIddict.
    /// </summary>
    public TimeSpan AuthenticationTimeout { get; set; } = TimeSpan.FromMinutes(5);
}
