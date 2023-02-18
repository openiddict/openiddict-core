/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.IO.Pipes;
using System.Runtime.Versioning;

namespace OpenIddict.Client.SystemIntegration;

/// <summary>
/// Provides various settings needed to configure the OpenIddict client system integration.
/// </summary>
public sealed class OpenIddictClientSystemIntegrationOptions
{
    /// <summary>
    /// Gets or sets the authentication mode used to start authentication flows.
    /// </summary>
    /// <remarks>
    /// If this property is not explicitly set, its value is automatically set by OpenIddict.
    /// </remarks>
    public OpenIddictClientSystemIntegrationAuthenticationMode? AuthenticationMode { get; set; }

    /// <summary>
    /// Gets or sets the timeout after which authentication demands
    /// that are not completed are automatically aborted by OpenIddict.
    /// </summary>
    public TimeSpan AuthenticationTimeout { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Gets the list of static ports the embedded web server will be allowed to
    /// listen on, if enabled. The first port in the list that is not already used
    /// by another program is automatically chosen and the other ports are ignored.
    /// </summary>
    /// <remarks>
    /// If this property is not explicitly set, a port in the 49152-65535
    /// dynamic ports range is automatically chosen by OpenIddict at runtime.
    /// </remarks>
    public List<int> AllowedEmbeddedWebServerPorts { get; } = new();

    /// <summary>
    /// Gets or sets a boolean indicating whether protocol activation processing should be enabled.
    /// </summary>
    /// <remarks>
    /// If this property is not explicitly set, its value is automatically set by OpenIddict
    /// depending on the capabilities of the system on which the application is running.
    /// </remarks>
    public bool? EnableActivationHandling { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether protocol activation redirection should be enabled.
    /// </summary>
    /// <remarks>
    /// If this property is not explicitly set, its value is automatically set by OpenIddict
    /// depending on the capabilities of the system on which the application is running.
    /// </remarks>
    public bool? EnableActivationRedirection { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether a local web server
    /// should be started on a random port to handle callbacks.
    /// </summary>
    /// <remarks>
    /// If this property is not explicitly set, its value is automatically set by OpenIddict
    /// depending on the capabilities of the system on which the application is running.
    /// </remarks>
    public bool? EnableEmbeddedWebServer { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether a pipe server should be started to process notifications
    /// (e.g protocol activation redirections) sent by other instances of the application.
    /// </summary>
    /// <remarks>
    /// If this property is not explicitly set, its value is automatically set by OpenIddict
    /// depending on the capabilities of the system on which the application is running.
    /// </remarks>
    public bool? EnablePipeServer { get; set; }

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
    /// Gets or sets the pipe options applied to the pipe created by OpenIddict to enable
    /// inter-process communication and handle protocol activation redirections.
    /// </summary>
    /// <remarks>
    /// If no value is explicitly set, a default combination is automatically used.
    /// </remarks>
    public PipeOptions? PipeOptions { get; set; }

    /// <summary>
    /// Gets or sets the security policy applied to the pipe created by OpenIddict
    /// to enable inter-process communication and handle protocol activation redirections.
    /// </summary>
    /// <remarks>
    /// If no value is explicitly set, a default policy is automatically created
    /// (unless the application is running inside an AppContainer sandbox).
    /// </remarks>
    [SupportedOSPlatform("windows")]
    public PipeSecurity? PipeSecurity { get; set; }
}
