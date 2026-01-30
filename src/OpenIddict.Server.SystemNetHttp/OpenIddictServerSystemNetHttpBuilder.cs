/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Reflection;
using OpenIddict.Server.SystemNetHttp;
using Polly;

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
    /// Sets the contact address used in the "From" header that is attached
    /// to the HTTP requests sent by the OpenIddict server services.
    /// </summary>
    /// <param name="address">The mail address.</param>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    public OpenIddictServerSystemNetHttpBuilder SetContactAddress(MailAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        return Configure(options => options.ContactAddress = address);
    }

    /// <summary>
    /// Sets the contact address used in the "From" header that is attached
    /// to the HTTP requests sent by the OpenIddict server services.
    /// </summary>
    /// <param name="address">The mail address.</param>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    public OpenIddictServerSystemNetHttpBuilder SetContactAddress(string address)
    {
        ArgumentException.ThrowIfNullOrEmpty(address);

        return SetContactAddress(new MailAddress(address));
    }

    /// <summary>
    /// Replaces the default HTTP error policy used by the OpenIddict server services.
    /// </summary>
    /// <param name="policy">The HTTP Polly error policy.</param>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    public OpenIddictServerSystemNetHttpBuilder SetHttpErrorPolicy(IAsyncPolicy<HttpResponseMessage> policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        return Configure(options => options.HttpErrorPolicy = policy);
    }

#if SUPPORTS_HTTP_CLIENT_RESILIENCE
    /// <summary>
    /// Replaces the default HTTP resilience pipeline used by the OpenIddict server services.
    /// </summary>
    /// <param name="configuration">
    /// The delegate used to configure the <see cref="ResiliencePipeline{HttpResponseMessage}"/>.
    /// </param>
    /// <remarks>
    /// Note: this option has no effect when an HTTP error policy was explicitly configured
    /// using <see cref="SetHttpErrorPolicy(IAsyncPolicy{HttpResponseMessage})"/>.
    /// </remarks>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    public OpenIddictServerSystemNetHttpBuilder SetHttpResiliencePipeline(
        Action<ResiliencePipelineBuilder<HttpResponseMessage>> configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var builder = new ResiliencePipelineBuilder<HttpResponseMessage>();
        configuration(builder);

        return SetHttpResiliencePipeline(builder.Build());
    }

    /// <summary>
    /// Replaces the default HTTP resilience pipeline used by the OpenIddict server services.
    /// </summary>
    /// <param name="pipeline">The HTTP resilience pipeline.</param>
    /// <remarks>
    /// Note: this option has no effect when an HTTP error policy was explicitly configured
    /// using <see cref="SetHttpErrorPolicy(IAsyncPolicy{HttpResponseMessage})"/>.
    /// </remarks>
    /// <returns>The <see cref="OpenIddictServerSystemNetHttpBuilder"/> instance.</returns>
    public OpenIddictServerSystemNetHttpBuilder SetHttpResiliencePipeline(ResiliencePipeline<HttpResponseMessage> pipeline)
    {
        ArgumentNullException.ThrowIfNull(pipeline);

        return Configure(options => options.HttpResiliencePipeline = pipeline);
    }
#endif

    /// <summary>
    /// Sets the product information used in the "User-Agent" header that is attached
    /// to the HTTP requests sent by the OpenIddict server services.
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
    /// to the HTTP requests sent by the OpenIddict server services.
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
    /// Sets the product information used in the user agent header that is attached
    /// to the HTTP requests sent by the OpenIddict server services based
    /// on the identity of the specified .NET assembly (name and version).
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
    public override bool Equals(object? obj) => base.Equals(obj);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}
