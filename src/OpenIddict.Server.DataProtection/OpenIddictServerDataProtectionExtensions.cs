/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using OpenIddict.Server.DataProtection;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict ASP.NET Core Data Protection server services.
/// </summary>
public static class OpenIddictServerDataProtectionExtensions
{
    /// <summary>
    /// Registers the OpenIddict ASP.NET Core Data Protection server services in the DI container
    /// and configures OpenIddict to validate and issue ASP.NET Data Protection-based tokens.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
    public static OpenIddictServerDataProtectionBuilder UseDataProtection(this OpenIddictServerBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        builder.Services.AddDataProtection();

        // Register the built-in server event handlers used by the OpenIddict Data Protection components.
        // Note: the order used here is not important, as the actual order is set in the options.
        builder.Services.TryAdd(OpenIddictServerDataProtectionHandlers.DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

        // Register the built-in filters used by the default OpenIddict Data Protection event handlers.
        builder.Services.TryAddSingleton<RequireDataProtectionTokenFormat>();

        // Note: TryAddEnumerable() is used here to ensure the initializers are registered only once.
        builder.Services.TryAddEnumerable(new[]
        {
            ServiceDescriptor.Singleton<IConfigureOptions<OpenIddictServerOptions>, OpenIddictServerDataProtectionConfiguration>(),
            ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIddictServerDataProtectionOptions>, OpenIddictServerDataProtectionConfiguration>()
        });

        return new OpenIddictServerDataProtectionBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict ASP.NET Core Data Protection server services in the DI container
    /// and configures OpenIddict to validate and issue ASP.NET Data Protection-based tokens.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the server services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
    public static OpenIddictServerBuilder UseDataProtection(
        this OpenIddictServerBuilder builder, Action<OpenIddictServerDataProtectionBuilder> configuration)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        configuration(builder.UseDataProtection());

        return builder;
    }
}
