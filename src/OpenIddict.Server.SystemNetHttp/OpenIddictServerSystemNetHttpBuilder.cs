/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Net.Http;
using OpenIddict.Server.SystemNetHttp;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict server/System.Net.Http integration.
/// </summary>
public sealed class OpenIddictServerSystemNetHttpBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictServerSystemNetHttpBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictServerSystemNetHttpBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the <see cref="HttpClient"/> used to send back-channel logout requests.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the <see cref="HttpClient"/>.</param>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    public OpenIddictServerSystemNetHttpBuilder ConfigureHttpClient(Action<HttpClient> configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        Services.AddHttpClient(OpenIddictServerSystemNetHttpConstants.HttpClientName).ConfigureHttpClient(configuration);

        return this;
    }

    /// <summary>
    /// Replaces the primary <see cref="HttpMessageHandler"/> used to send back-channel logout requests.
    /// </summary>
    /// <param name="factory">The delegate used to create the primary <see cref="HttpMessageHandler"/>.</param>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    public OpenIddictServerSystemNetHttpBuilder ConfigurePrimaryHttpMessageHandler(Func<HttpMessageHandler> factory)
    {
        ArgumentNullException.ThrowIfNull(factory);

        Services.AddHttpClient(OpenIddictServerSystemNetHttpConstants.HttpClientName).ConfigurePrimaryHttpMessageHandler(factory);

        return this;
    }
}
