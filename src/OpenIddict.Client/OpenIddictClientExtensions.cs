/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Client;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict client services.
/// </summary>
public static class OpenIddictClientExtensions
{
    /// <summary>
    /// Registers the OpenIddict client services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public static OpenIddictClientBuilder AddClient(this OpenIddictBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        builder.Services.AddLogging();
        builder.Services.AddOptions();

        builder.Services.TryAddScoped<IOpenIddictClientDispatcher, OpenIddictClientDispatcher>();
        builder.Services.TryAddScoped<IOpenIddictClientFactory, OpenIddictClientFactory>();
        builder.Services.TryAddSingleton<OpenIddictClientService>();

        // Register the built-in filters used by the default OpenIddict client event handlers.
        builder.Services.TryAddSingleton<RequireAuthorizationCodeOrImplicitGrantType>();
        builder.Services.TryAddSingleton<RequireAuthorizationCodeValidated>();
        builder.Services.TryAddSingleton<RequireBackchannelAccessTokenValidated>();
        builder.Services.TryAddSingleton<RequireBackchannelIdentityTokenValidated>();
        builder.Services.TryAddSingleton<RequireBackchannelIdentityTokenPrincipal>();
        builder.Services.TryAddSingleton<RequireClientAssertionTokenGenerated>();
        builder.Services.TryAddSingleton<RequireFrontchannelAccessTokenValidated>();
        builder.Services.TryAddSingleton<RequireFrontchannelIdentityTokenValidated>();
        builder.Services.TryAddSingleton<RequireFrontchannelIdentityTokenPrincipal>();
        builder.Services.TryAddSingleton<RequireRedirectionRequest>();
        builder.Services.TryAddSingleton<RequireRefreshTokenValidated>();
        builder.Services.TryAddSingleton<RequireStateTokenGenerated>();
        builder.Services.TryAddSingleton<RequireStateTokenPrincipal>();
        builder.Services.TryAddSingleton<RequireStateTokenValidated>();
        builder.Services.TryAddSingleton<RequireTokenEntryCreated>();
        builder.Services.TryAddSingleton<RequireTokenPayloadPersisted>();
        builder.Services.TryAddSingleton<RequireTokenRequest>();
        builder.Services.TryAddSingleton<RequireTokenStorageEnabled>();
        builder.Services.TryAddSingleton<RequireUserinfoRequest>();
        builder.Services.TryAddSingleton<RequireUserinfoTokenExtracted>();
        builder.Services.TryAddSingleton<RequireUserinfoTokenPrincipal>();

        // Register the built-in client event handlers used by the OpenIddict client components.
        // Note: the order used here is not important, as the actual order is set in the options.
        builder.Services.TryAdd(DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

        // Note: TryAddEnumerable() is used here to ensure the initializer is registered only once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictClientOptions>, OpenIddictClientConfiguration>());

        return new OpenIddictClientBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict client services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the client services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
    public static OpenIddictBuilder AddClient(this OpenIddictBuilder builder, Action<OpenIddictClientBuilder> configuration)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        configuration(builder.AddClient());

        return builder;
    }
}
