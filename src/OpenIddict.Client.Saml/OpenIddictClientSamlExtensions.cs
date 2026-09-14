/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Client.Saml;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict SAML 2.0 service provider services.
/// </summary>
public static class OpenIddictClientSamlExtensions
{
    /// <summary>
    /// Registers the OpenIddict SAML 2.0 service provider services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public static OpenIddictClientSamlBuilder UseSaml(this OpenIddictClientBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddLogging();
        builder.Services.AddOptions();

        builder.Services.TryAddSingleton<OpenIddictClientSamlService>();
        builder.Services.TryAddSingleton<IOpenIddictClientSamlMetadataRetriever, OpenIddictClientSamlMetadataRetriever>();
        builder.Services.TryAddSingleton<IOpenIddictClientSamlReplayCache, OpenIddictClientSamlReplayCache>();

        // Note: the built-in provider returning the static registrations is always queried first.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IOpenIddictClientSamlRegistrationProvider, OpenIddictClientSamlRegistrationProvider>());

        // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictClientSamlOptions>, OpenIddictClientSamlConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IValidateOptions<OpenIddictClientSamlOptions>, OpenIddictClientSamlConfiguration>());

        return new OpenIddictClientSamlBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict SAML 2.0 service provider services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the SAML services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public static OpenIddictClientBuilder UseSaml(
        this OpenIddictClientBuilder builder, Action<OpenIddictClientSamlBuilder> configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        configuration(builder.UseSaml());

        return builder;
    }
}
