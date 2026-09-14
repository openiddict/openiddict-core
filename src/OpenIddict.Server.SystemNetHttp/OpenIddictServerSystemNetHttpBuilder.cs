/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
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
    /// Amends the default OpenIddict server/System.Net.Http configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerSystemNetHttpBuilder Configure(Action<OpenIddictServerSystemNetHttpOptions> configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Configures the <see cref="HttpClient"/> used by the OpenIddict server/System.Net.Http integration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the <see cref="HttpClient"/>.</param>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerSystemNetHttpBuilder ConfigureHttpClient(Action<HttpClient> configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        return Configure(options => options.HttpClientActions.Add(configuration));
    }

    /// <summary>
    /// Configures the <see cref="HttpClientHandler"/> used by the OpenIddict server/System.Net.Http integration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the <see cref="HttpClientHandler"/>.</param>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerSystemNetHttpBuilder ConfigureHttpClientHandler(Action<HttpClientHandler> configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        return Configure(options => options.HttpClientHandlerActions.Add(configuration));
    }

    /// <summary>
    /// Replaces the primary <see cref="HttpMessageHandler"/> used by the OpenIddict server/System.Net.Http integration.
    /// </summary>
    /// <param name="factory">The delegate used to create the primary <see cref="HttpMessageHandler"/>.</param>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerSystemNetHttpBuilder ConfigurePrimaryHttpMessageHandler(Func<HttpMessageHandler> factory)
    {
        ArgumentNullException.ThrowIfNull(factory);

        Services.AddHttpClient(OpenIddictServerSystemNetHttpConstants.HttpClientName).ConfigurePrimaryHttpMessageHandler(factory);

        return this;
    }

    /// <summary>
    /// Sets the timeout applied to the HTTP requests sent to client notification and back-channel logout endpoints.
    /// </summary>
    /// <param name="timeout">The timeout.</param>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    public OpenIddictServerSystemNetHttpBuilder SetTimeout(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        return Configure(options => options.Timeout = timeout);
    }

    /// <summary>
    /// Sets the product information used in the "User-Agent" header that is attached
    /// to the HTTP requests sent to client notification endpoints.
    /// </summary>
    /// <param name="information">The product information.</param>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    public OpenIddictServerSystemNetHttpBuilder SetProductInformation(ProductInfoHeaderValue information)
    {
        ArgumentNullException.ThrowIfNull(information);

        return Configure(options => options.ProductInformation = information);
    }

    /// <summary>
    /// Sets the product information used in the "User-Agent" header that is attached
    /// to the HTTP requests sent to client notification endpoints.
    /// </summary>
    /// <param name="name">The product name.</param>
    /// <param name="version">The product version.</param>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    public OpenIddictServerSystemNetHttpBuilder SetProductInformation(string name, string? version)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        return SetProductInformation(new ProductInfoHeaderValue(name, version));
    }

    /// <summary>
    /// Sets the product information used in the "User-Agent" header based on
    /// the identity of the specified .NET assembly (name and version).
    /// </summary>
    /// <param name="assembly">The assembly from which the product information is created.</param>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    public OpenIddictServerSystemNetHttpBuilder SetProductInformation(Assembly assembly)
    {
        ArgumentNullException.ThrowIfNull(assembly);

        return SetProductInformation(new ProductInfoHeaderValue(
            productName: assembly.GetName().Name!,
            productVersion: assembly.GetName().Version!.ToString()));
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => base.Equals(obj);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}
