/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
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
    public OpenIddictClientSystemNetHttpBuilder(IServiceCollection services!!)
        => Services = services;

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
    public OpenIddictClientSystemNetHttpBuilder Configure(Action<OpenIddictClientSystemNetHttpOptions> configuration!!)
    {
        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Replaces the default HTTP error policy used by the OpenIddict client services.
    /// </summary>
    /// <param name="policy">The HTTP Polly error policy.</param>
    /// <returns>The <see cref="OpenIddictClientSystemNetHttpBuilder"/>.</returns>
    public OpenIddictClientSystemNetHttpBuilder SetHttpErrorPolicy(IAsyncPolicy<HttpResponseMessage> policy)
        => Configure(options => options.HttpErrorPolicy = policy);

    /// <summary>
    /// Determines whether the specified object is equal to the current object.
    /// </summary>
    /// <param name="obj">The object to compare with the current object.</param>
    /// <returns><c>true</c> if the specified object is equal to the current object; otherwise, false.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => base.Equals(obj);

    /// <summary>
    /// Serves as the default hash function.
    /// </summary>
    /// <returns>A hash code for the current object.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <summary>
    /// Returns a string that represents the current object.
    /// </summary>
    /// <returns>A string that represents the current object.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}
