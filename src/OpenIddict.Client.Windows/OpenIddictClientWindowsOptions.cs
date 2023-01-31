/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.IO.Pipes;
using Microsoft.Extensions.Hosting;

#if !SUPPORTS_HOST_ENVIRONMENT
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
#endif

namespace OpenIddict.Client.Windows;

/// <summary>
/// Provides various settings needed to configure the OpenIddict Windows client integration.
/// </summary>
public sealed class OpenIddictClientWindowsOptions
{
    /// <summary>
    /// Gets or sets the timeout after which authentication demands
    /// that are not completed are automatically aborted by OpenIddict.
    /// </summary>
    public TimeSpan AuthenticationTimeout { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Gets or sets the identifier used to represent the current application
    /// instance and redirect protocol activations when necessary.
    /// </summary>
    public string? InstanceIdentifier { get; set; }

    /// <summary>
    /// Gets or sets the base name of the pipe created by OpenIddict to enable
    /// inter-process communication and handle protocol activation redirections.
    /// </summary>
    /// <remarks>
    /// If no value is explicitly set, a default name is automatically computed.
    /// </remarks>
    public string PipeName { get; set; } = default!;

    /// <summary>
    /// Gets or sets the security policy applied to the pipe created by OpenIddict
    /// to enable inter-process communication and handle protocol activation redirections.
    /// </summary>
    /// <remarks>
    /// If no value is explicitly set, a default policy is automatically created
    /// (unless the application is running inside an AppContainer sandbox).
    /// </remarks>
    public PipeSecurity PipeSecurity { get; set; } = default!;
}
