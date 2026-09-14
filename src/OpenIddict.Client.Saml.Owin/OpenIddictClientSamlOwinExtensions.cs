/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Client.Saml.Owin;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict SAML service provider OWIN/Katana integration services.
/// </summary>
public static class OpenIddictClientSamlOwinExtensions
{
    /// <summary>
    /// Registers the OpenIddict SAML service provider OWIN/Katana integration services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientSamlOwinBuilder"/> instance.</returns>
    public static OpenIddictClientSamlOwinBuilder UseOwin(this OpenIddictClientSamlBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddDataProtection();

        builder.Services.TryAddSingleton<OpenIddictClientSamlOwinStateProtector>();

        // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IValidateOptions<OpenIddictClientSamlOwinOptions>, OpenIddictClientSamlOwinConfiguration>());

        return new OpenIddictClientSamlOwinBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict SAML service provider OWIN/Katana integration services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the SAML OWIN/Katana services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public static OpenIddictClientSamlBuilder UseOwin(
        this OpenIddictClientSamlBuilder builder, Action<OpenIddictClientSamlOwinBuilder> configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        configuration(builder.UseOwin());

        return builder;
    }
}
