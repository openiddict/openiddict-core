/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Server;
using OpenIddict.Server.SystemNetHttp;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict server/System.Net.Http integration services.
/// </summary>
public static class OpenIddictServerSystemNetHttpExtensions
{
    /// <summary>
    /// Registers the OpenIddict server/System.Net.Http integration services in the DI container,
    /// used to send the back-channel logout requests (OpenID Connect Back-Channel Logout 1.0).
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    public static OpenIddictServerSystemNetHttpBuilder UseSystemNetHttp(this OpenIddictServerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Note: redirections are not followed, as back-channel logout requests are expected to be
        // directly processed by the back-channel logout URI registered by the client application.
        builder.Services.AddHttpClient(OpenIddictServerSystemNetHttpConstants.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(static () => new HttpClientHandler { AllowAutoRedirect = false });

        // Register the built-in server event handlers used by the OpenIddict System.Net.Http components.
        // Note: the order used here is not important, as the actual order is set in the options.
        builder.Services.TryAdd(OpenIddictServerSystemNetHttpHandlers.DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

        builder.Configure(options =>
        {
            foreach (var descriptor in OpenIddictServerSystemNetHttpHandlers.DefaultHandlers)
            {
                if (!options.Handlers.Contains(descriptor))
                {
                    options.Handlers.Add(descriptor);
                }
            }
        });

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
