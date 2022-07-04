/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using OpenIddict.Client.Maui;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure
/// the OpenIddict client MAUI integration.
/// </summary>
public class OpenIddictClientMauiBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictClientMauiBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictClientMauiBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict client MAUI configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientMauiBuilder"/>.</returns>
    public OpenIddictClientMauiBuilder Configure(Action<OpenIddictClientMauiOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Sets the timeout after which authentication demands that
    /// are not completed are automatically aborted by OpenIddict.
    /// </summary>
    /// <param name="timeout">The authentication timeout.</param>
    /// <returns>The <see cref="OpenIddictClientMauiBuilder"/>.</returns>
    public OpenIddictClientMauiBuilder SetAuthenticationTimeout(TimeSpan timeout)
        => Configure(options => options.AuthenticationTimeout = timeout);

    /// <summary>
    /// Determines whether the specified object is equal to the current object.
    /// </summary>
    /// <param name="obj">The object to compare with the current object.</param>
    /// <returns><see langword="true"/> if the specified object is equal to the current object; otherwise, false.</returns>
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
