/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.DataProtection;

namespace OpenIddict.Client.DataProtection;

/// <summary>
/// Provides various settings needed to configure the OpenIddict
/// ASP.NET Core Data Protection server integration.
/// </summary>
public sealed class OpenIddictClientDataProtectionOptions
{
    /// <summary>
    /// Gets or sets the data protection provider used to create the default
    /// data protectors used by the OpenIddict Data Protection client services.
    /// When this property is set to <see langword="null"/>, the data protection provider
    /// is directly retrieved from the dependency injection container.
    /// </summary>
    public IDataProtectionProvider DataProtectionProvider { get; set; } = default!;

    /// <summary>
    /// Gets or sets the formatter used to read and write Data Protection tokens.
    /// </summary>
    public IOpenIddictClientDataProtectionFormatter Formatter { get; set; }
        = new OpenIddictClientDataProtectionFormatter();

    /// <summary>
    /// Gets or sets a boolean indicating whether the default state token format should be
    /// used when issuing new state tokens. This property is set to <see langword="false"/> by default.
    /// </summary>
    public bool PreferDefaultStateTokenFormat { get; set; }
}
