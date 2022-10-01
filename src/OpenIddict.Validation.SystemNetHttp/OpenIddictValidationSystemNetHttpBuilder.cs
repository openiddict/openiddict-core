/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Net.Http.Headers;
using System.Reflection;
using OpenIddict.Validation.SystemNetHttp;
using Polly;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict validation/System.Net.Http integration.
/// </summary>
public class OpenIddictValidationSystemNetHttpBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictValidationBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictValidationSystemNetHttpBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict validation/server integration configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictValidationSystemNetHttpBuilder"/>.</returns>
    public OpenIddictValidationSystemNetHttpBuilder Configure(Action<OpenIddictValidationSystemNetHttpOptions> configuration)
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
    /// <returns>The <see cref="OpenIddictValidationSystemNetHttpBuilder"/>.</returns>
    public OpenIddictValidationSystemNetHttpBuilder SetHttpErrorPolicy(IAsyncPolicy<HttpResponseMessage> policy)
    {
        if (policy is null)
        {
            throw new ArgumentNullException(nameof(policy));
        }

        return Configure(options => options.HttpErrorPolicy = policy);
    }

    /// <summary>
    /// Sets the product information used in the user agent header that is attached
    /// to the backchannel HTTP requests sent to the authorization server.
    /// </summary>
    /// <param name="information">The product information.</param>
    /// <returns>The <see cref="OpenIddictValidationSystemNetHttpBuilder"/>.</returns>
    public OpenIddictValidationSystemNetHttpBuilder SetProductInformation(ProductInfoHeaderValue information)
    {
        if (information is null)
        {
            throw new ArgumentNullException(nameof(information));
        }

        return Configure(options => options.ProductInformation = information);
    }

    /// <summary>
    /// Sets the product information used in the user agent header that is attached
    /// to the backchannel HTTP requests sent to the authorization server.
    /// </summary>
    /// <param name="name">The product name.</param>
    /// <param name="version">The product version.</param>
    /// <returns>The <see cref="OpenIddictValidationSystemNetHttpBuilder"/>.</returns>
    public OpenIddictValidationSystemNetHttpBuilder SetProductInformation(string name, string? version)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0345), nameof(name));
        }

        return SetProductInformation(new ProductInfoHeaderValue(name, version));
    }

    /// <summary>
    /// Sets the product information used in the user agent header that is attached
    /// to the backchannel HTTP requests sent to the authorization server based
    /// on the identity of the specified .NET assembly (name and version).
    /// </summary>
    /// <param name="assembly">The assembly from which the product information is created.</param>
    /// <returns>The <see cref="OpenIddictValidationSystemNetHttpBuilder"/>.</returns>
    public OpenIddictValidationSystemNetHttpBuilder SetProductInformation(Assembly assembly)
    {
        if (assembly is null)
        {
            throw new ArgumentNullException(nameof(assembly));
        }

        return SetProductInformation(new ProductInfoHeaderValue(
            productName: assembly.GetName().Name!,
            productVersion: assembly.GetName().Version!.ToString()));
    }

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
