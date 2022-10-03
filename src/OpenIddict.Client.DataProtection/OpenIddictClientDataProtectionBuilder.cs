/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.AspNetCore.DataProtection;
using OpenIddict.Client.DataProtection;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the
/// OpenIddict ASP.NET Core Data Protection integration.
/// </summary>
public class OpenIddictClientDataProtectionBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictClientDataProtectionBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictClientDataProtectionBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict client ASP.NET Core Data Protection configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientDataProtectionBuilder"/> instance.</returns>
    public OpenIddictClientDataProtectionBuilder Configure(Action<OpenIddictClientDataProtectionOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Configures OpenIddict to use a specific data protection provider
    /// instead of relying on the default instance provided by the DI container.
    /// </summary>
    /// <param name="provider">The data protection provider used to create token protectors.</param>
    /// <returns>The <see cref="OpenIddictClientDataProtectionBuilder"/> instance.</returns>
    public OpenIddictClientDataProtectionBuilder UseDataProtectionProvider(IDataProtectionProvider provider)
    {
        if (provider is null)
        {
            throw new ArgumentNullException(nameof(provider));
        }

        return Configure(options => options.DataProtectionProvider = provider);
    }

    /// <summary>
    /// Configures OpenIddict to use a specific formatter instead of relying on the default instance.
    /// </summary>
    /// <param name="formatter">The formatter used to read and write tokens.</param>
    /// <returns>The <see cref="OpenIddictClientDataProtectionBuilder"/> instance.</returns>
    public OpenIddictClientDataProtectionBuilder UseFormatter(IOpenIddictClientDataProtectionFormatter formatter)
    {
        if (formatter is null)
        {
            throw new ArgumentNullException(nameof(formatter));
        }

        return Configure(options => options.Formatter = formatter);
    }

    /// <summary>
    /// Configures OpenIddict to use the default token format (JWT) when issuing new state tokens.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientDataProtectionBuilder"/> instance.</returns>
    public OpenIddictClientDataProtectionBuilder PreferDefaultStateTokenFormat()
        => Configure(options => options.PreferDefaultStateTokenFormat = true);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => base.Equals(obj);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}
