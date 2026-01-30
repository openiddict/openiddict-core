/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using OpenIddict.Server.SystemNetHttp;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict server/System.Net.Http integration services.
/// </summary>
public static class OpenIddictServerSystemNetHttpExtensions
{
    /// <summary>
    /// Registers the OpenIddict server/System.Net.Http integration services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    public static OpenIddictServerSystemNetHttpBuilder UseSystemNetHttp(this OpenIddictServerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddHttpClient();

        // Register the built-in event handlers used by the OpenIddict System.Net.Http components.
        // Note: the order used here is not important, as the actual order is set in the options.
        builder.Services.TryAdd(OpenIddictServerSystemNetHttpHandlers.DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

        // Register the built-in filters used by the default OpenIddict System.Net.Http event handlers.
        builder.Services.TryAddSingleton<RequireClientIdMetadataDocumentSupportEnabled>();

        // Note: TryAddEnumerable() is used here to ensure the initializers are registered only once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IConfigureOptions<OpenIddictServerOptions>, OpenIddictServerSystemNetHttpConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IConfigureOptions<HttpClientFactoryOptions>, OpenIddictServerSystemNetHttpConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<HttpClientFactoryOptions>, OpenIddictServerSystemNetHttpConfiguration>());

        return new OpenIddictServerSystemNetHttpBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict server/System.Net.Http integration services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the server services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public static OpenIddictServerBuilder UseSystemNetHttp(
        this OpenIddictServerBuilder builder, Action<OpenIddictServerSystemNetHttpBuilder> configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        configuration(builder.UseSystemNetHttp());

        return builder;
    }
}
