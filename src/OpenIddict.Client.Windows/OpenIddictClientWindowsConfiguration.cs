/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;

#if !SUPPORTS_HOST_ENVIRONMENT
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
#endif

namespace OpenIddict.Client.Windows;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict client configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientWindowsConfiguration : IConfigureOptions<OpenIddictClientOptions>,
                                                           IPostConfigureOptions<OpenIddictClientOptions>,
                                                           IPostConfigureOptions<OpenIddictClientWindowsOptions>
{
    private readonly IHostEnvironment _environment;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientWindowsConfiguration"/> class.
    /// </summary>
    /// <param name="environment">The host environment.</param>
    public OpenIddictClientWindowsConfiguration(IHostEnvironment environment)
        => _environment = environment ?? throw new ArgumentNullException(nameof(environment));

    /// <inheritdoc/>
    public void Configure(OpenIddictClientOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Register the built-in event handlers used by the OpenIddict Windows client components.
        options.Handlers.AddRange(OpenIddictClientWindowsHandlers.DefaultHandlers);
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictClientOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Ensure an explicit client URI was set when using the Windows integration.
        if (options.ClientUri is not { IsAbsoluteUri: true })
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0384));
        }
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictClientWindowsOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // If no explicit instance identifier was specified, use a random GUID.
        if (string.IsNullOrEmpty(options.InstanceIdentifier))
        {
            options.InstanceIdentifier = Guid.NewGuid().ToString();
        }

        // If no explicit pipe name was specified, compute the SHA-256 hash of the
        // application name resolved from the host and use it as a unique identifier.
        //
        // Note: the pipe name is deliberately prefixed with "LOCAL\" to support
        // partial trust/sandboxed applications that are executed in an AppContainer
        // and cannot communicate with applications outside the sandbox container.
        if (string.IsNullOrEmpty(options.PipeName))
        {
            options.PipeName = $@"LOCAL\OpenIddict.Client.Windows\{
                Base64UrlEncoder.Encode(OpenIddictHelpers.ComputeSha256Hash(
                    Encoding.UTF8.GetBytes(_environment.ApplicationName)))
            }";
        }

        // If no explicit pipe security policy was specified, grant the current user
        // full control over the created pipe and allow cross-process communication
        // between elevated and non-elevated processes.
        if (options.PipeSecurity is null)
        {
            using var identity = WindowsIdentity.GetCurrent();

            options.PipeSecurity = new PipeSecurity();
            options.PipeSecurity.SetOwner(identity.User!);
            options.PipeSecurity.AddAccessRule(new PipeAccessRule(identity.User!,
                PipeAccessRights.FullControl, AccessControlType.Allow));
        }
    }
}
