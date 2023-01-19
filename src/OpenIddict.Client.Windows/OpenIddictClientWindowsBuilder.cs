/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.IO.Pipes;
using OpenIddict.Client.Windows;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure
/// the OpenIddict client Windows integration.
/// </summary>
public sealed class OpenIddictClientWindowsBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictClientWindowsBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictClientWindowsBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict client Windows configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientWindowsBuilder"/>.</returns>
    public OpenIddictClientWindowsBuilder Configure(Action<OpenIddictClientWindowsOptions> configuration)
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
    /// <returns>The <see cref="OpenIddictClientWindowsBuilder"/>.</returns>
    public OpenIddictClientWindowsBuilder SetAuthenticationTimeout(TimeSpan timeout)
        => Configure(options => options.AuthenticationTimeout = timeout);

    /// <summary>
    /// Sets the identifier used to represent the current application
    /// instance and redirect protocol activations when necessary.
    /// </summary>
    /// <param name="identifier">The identifier of the current instance.</param>
    /// <returns>The <see cref="OpenIddictClientWindowsBuilder"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientWindowsBuilder SetInstanceIdentifier(string identifier)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(identifier)), nameof(identifier));
        }

        return Configure(options => options.InstanceIdentifier = identifier);
    }

    /// <summary>
    /// Sets the base name of the pipe created by OpenIddict to enable
    /// inter-process communication and handle protocol activation redirections.
    /// </summary>
    /// <param name="name">The name of the pipe.</param>
    /// <returns>The <see cref="OpenIddictClientWindowsBuilder"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientWindowsBuilder SetPipeName(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(name)), nameof(name));
        }

        return Configure(options => options.PipeName = name);
    }

    /// <summary>
    /// Sets the security policy applied to the pipe created by OpenIddict to enable
    /// inter-process communication and handle protocol activation redirections.
    /// </summary>
    /// <param name="security">The security policy applied to the pipe.</param>
    /// <returns>The <see cref="OpenIddictClientWindowsBuilder"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientWindowsBuilder SetPipeSecurity(PipeSecurity security)
    {
        if (security is null)
        {
            throw new ArgumentNullException(nameof(security));
        }

        return Configure(options => options.PipeSecurity = security);
    }

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
