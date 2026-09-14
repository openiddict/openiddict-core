/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Server.Saml;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict SAML 2.0 identity provider services.
/// </summary>
public static class OpenIddictServerSamlExtensions
{
    /// <summary>
    /// Registers the OpenIddict SAML 2.0 identity provider services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public static OpenIddictServerSamlBuilder UseSaml(this OpenIddictServerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddLogging();
        builder.Services.AddOptions();

        builder.Services.TryAddSingleton<IOpenIddictServerSamlServiceProviderStore, OpenIddictServerSamlServiceProviderStore>();
        builder.Services.TryAddSingleton<IOpenIddictServerSamlAssertionProvider, OpenIddictServerSamlAssertionProvider>();
        builder.Services.TryAddSingleton<IOpenIddictServerSamlArtifactStore, OpenIddictServerSamlArtifactStore>();
        builder.Services.TryAddSingleton<IOpenIddictServerSamlReplayCache, OpenIddictServerSamlReplayCache>();
        builder.Services.TryAddScoped<OpenIddictServerSamlService>();

        // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictServerSamlOptions>, OpenIddictServerSamlConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IValidateOptions<OpenIddictServerSamlOptions>, OpenIddictServerSamlConfiguration>());

        return new OpenIddictServerSamlBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict SAML 2.0 identity provider services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the SAML services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public static OpenIddictServerBuilder UseSaml(
        this OpenIddictServerBuilder builder, Action<OpenIddictServerSamlBuilder> configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        configuration(builder.UseSaml());

        return builder;
    }
}
