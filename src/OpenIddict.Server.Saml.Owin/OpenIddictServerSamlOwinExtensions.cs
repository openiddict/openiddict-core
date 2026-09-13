/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Server.Saml.Owin;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict SAML OWIN/Katana integration services.
/// </summary>
public static class OpenIddictServerSamlOwinExtensions
{
    /// <summary>
    /// Registers the OpenIddict SAML OWIN/Katana integration services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerSamlOwinBuilder"/> instance.</returns>
    public static OpenIddictServerSamlOwinBuilder UseOwin(this OpenIddictServerSamlBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddDataProtection();

        builder.Services.TryAddSingleton<OpenIddictServerSamlOwinStateProtector>();

        // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IValidateOptions<OpenIddictServerSamlOwinOptions>, OpenIddictServerSamlOwinConfiguration>());

        return new OpenIddictServerSamlOwinBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict SAML OWIN/Katana integration services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the SAML OWIN/Katana services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public static OpenIddictServerSamlBuilder UseOwin(
        this OpenIddictServerSamlBuilder builder, Action<OpenIddictServerSamlOwinBuilder> configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        configuration(builder.UseOwin());

        return builder;
    }
}
