/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Net.Http.Headers;
using OpenIddict.Client.SystemNetHttp;
using Polly;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict client/System.Net.Http integration.
/// </summary>
public class OpenIddictClientSystemNetHttpBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictClientBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictClientSystemNetHttpBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict client/server integration configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientSystemNetHttpBuilder"/>.</returns>
    public OpenIddictClientSystemNetHttpBuilder Configure(Action<OpenIddictClientSystemNetHttpOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Replaces the default HTTP error policy used by the OpenIddict client services.
    /// </summary>
    /// <param name="policy">The HTTP Polly error policy.</param>
    /// <returns>The <see cref="OpenIddictClientSystemNetHttpBuilder"/>.</returns>
    public OpenIddictClientSystemNetHttpBuilder SetHttpErrorPolicy(IAsyncPolicy<HttpResponseMessage>? policy)
        => Configure(options => options.HttpErrorPolicy = policy);

    /// <summary>
    /// Sets the product information used in the user agent header that is attached
    /// to the backchannel HTTP requests sent to the authorization server.
    /// </summary>
    /// <param name="information">The product information.</param>
    /// <returns>The <see cref="OpenIddictClientSystemNetHttpBuilder"/>.</returns>
    public OpenIddictClientSystemNetHttpBuilder SetProductInformation(ProductInfoHeaderValue? information)
        => Configure(options => options.ProductInformation = information);

    /// <summary>
    /// Sets the product information used in the user agent header that is attached
    /// to the backchannel HTTP requests sent to the authorization server.
    /// </summary>
    /// <param name="name">The product name.</param>
    /// <param name="version">The product version.</param>
    /// <returns>The <see cref="OpenIddictClientSystemNetHttpBuilder"/>.</returns>
    public OpenIddictClientSystemNetHttpBuilder SetProductInformation(string? name, string? version)
        => SetProductInformation(!string.IsNullOrEmpty(name) ? new ProductInfoHeaderValue(name, version) : null);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => base.Equals(obj);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}
