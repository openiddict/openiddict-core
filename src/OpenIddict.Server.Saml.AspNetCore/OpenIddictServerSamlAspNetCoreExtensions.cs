/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Server.Saml.AspNetCore;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict SAML ASP.NET Core integration services.
/// </summary>
public static class OpenIddictServerSamlAspNetCoreExtensions
{
    /// <summary>
    /// Registers the OpenIddict SAML ASP.NET Core integration services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerSamlAspNetCoreBuilder"/> instance.</returns>
    public static OpenIddictServerSamlAspNetCoreBuilder UseAspNetCore(this OpenIddictServerSamlBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddAuthentication();
        builder.Services.AddDataProtection();

        builder.Services.TryAddSingleton<OpenIddictServerSamlAspNetCoreStateProtector>();

        // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IValidateOptions<OpenIddictServerSamlAspNetCoreOptions>, OpenIddictServerSamlAspNetCoreConfiguration>());

        return new OpenIddictServerSamlAspNetCoreBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict SAML ASP.NET Core integration services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the SAML ASP.NET Core services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public static OpenIddictServerSamlBuilder UseAspNetCore(
        this OpenIddictServerSamlBuilder builder, Action<OpenIddictServerSamlAspNetCoreBuilder> configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        configuration(builder.UseAspNetCore());

        return builder;
    }
}
