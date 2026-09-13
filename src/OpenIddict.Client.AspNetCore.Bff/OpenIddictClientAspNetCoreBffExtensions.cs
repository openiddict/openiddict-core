/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Client.AspNetCore.Bff;
using static OpenIddict.Client.AspNetCore.Bff.OpenIddictClientAspNetCoreBffModels;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict backend-for-frontend (BFF) services.
/// </summary>
public static class OpenIddictClientAspNetCoreBffExtensions
{
    /// <summary>
    /// Registers the OpenIddict backend-for-frontend (BFF) services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    public static OpenIddictClientAspNetCoreBffBuilder UseBff(this OpenIddictClientBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // The BFF components rely on the OpenIddict client ASP.NET Core integration.
        builder.UseAspNetCore();

        builder.Services.AddHttpContextAccessor();

        builder.Services.TryAddSingleton<OpenIddictClientAspNetCoreBffTokenManager>();
        builder.Services.TryAddSingleton<OpenIddictClientAspNetCoreBffLogoutTokenValidator>();

        builder.Services.TryAddEnumerable(ServiceDescriptor.Scoped<
            IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler, OpenIddictClientAspNetCoreBffSessionStoreLogoutHandler>());

        // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictClientOptions>, OpenIddictClientAspNetCoreBffConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictClientAspNetCoreOptions>, OpenIddictClientAspNetCoreBffConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<CookieAuthenticationOptions>, OpenIddictClientAspNetCoreBffConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IValidateOptions<OpenIddictClientAspNetCoreBffOptions>, OpenIddictClientAspNetCoreBffConfiguration>());

        return new OpenIddictClientAspNetCoreBffBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict backend-for-frontend (BFF) services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the BFF services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public static OpenIddictClientBuilder UseBff(
        this OpenIddictClientBuilder builder, Action<OpenIddictClientAspNetCoreBffBuilder> configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        configuration(builder.UseBff());

        return builder;
    }

    /// <summary>
    /// Adds a handler attaching the access token of the current user to the requests sent by the HTTP client.
    /// </summary>
    /// <param name="builder">The HTTP client builder.</param>
    /// <returns>The <see cref="IHttpClientBuilder"/> instance.</returns>
    public static IHttpClientBuilder AddOpenIddictBffUserAccessTokenHandler(this IHttpClientBuilder builder)
        => builder.AddOpenIddictBffAccessTokenHandler(OpenIddictClientAspNetCoreBffTokenType.User);

    /// <summary>
    /// Adds a handler attaching an access token obtained using the client
    /// credentials grant to the requests sent by the HTTP client.
    /// </summary>
    /// <param name="builder">The HTTP client builder.</param>
    /// <param name="request">The client access token request, if applicable.</param>
    /// <returns>The <see cref="IHttpClientBuilder"/> instance.</returns>
    public static IHttpClientBuilder AddOpenIddictBffClientAccessTokenHandler(
        this IHttpClientBuilder builder, ClientAccessTokenRequest? request = null)
        => builder.AddOpenIddictBffAccessTokenHandler(OpenIddictClientAspNetCoreBffTokenType.Client, request);

    /// <summary>
    /// Adds a handler attaching the specified type of access token to the requests sent by the HTTP client.
    /// </summary>
    /// <param name="builder">The HTTP client builder.</param>
    /// <param name="type">The type of access token.</param>
    /// <param name="request">The client access token request, if applicable.</param>
    /// <returns>The <see cref="IHttpClientBuilder"/> instance.</returns>
    public static IHttpClientBuilder AddOpenIddictBffAccessTokenHandler(this IHttpClientBuilder builder,
        OpenIddictClientAspNetCoreBffTokenType type, ClientAccessTokenRequest? request = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.AddHttpMessageHandler(provider => new OpenIddictClientAspNetCoreBffAccessTokenHandler(
            provider.GetRequiredService<IHttpContextAccessor>(),
            provider.GetService<OpenIddictClientAspNetCoreBffTokenManager>() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0561)),
            type, request));
    }

    /// <summary>
    /// Registers the YARP transforms attaching the user or client access tokens to proxied requests
    /// (see <see cref="OpenIddictClientAspNetCoreBffConstants.Metadata.AccessToken"/>).
    /// </summary>
    /// <param name="builder">The reverse proxy builder.</param>
    /// <returns>The <see cref="IReverseProxyBuilder"/> instance.</returns>
    public static IReverseProxyBuilder AddOpenIddictBffTransforms(this IReverseProxyBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.AddTransforms<OpenIddictClientAspNetCoreBffTransformProvider>();
    }
}
