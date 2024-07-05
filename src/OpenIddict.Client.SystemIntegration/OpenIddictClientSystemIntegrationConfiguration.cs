/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.IO.Pipes;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;
using static OpenIddict.Client.SystemIntegration.OpenIddictClientSystemIntegrationAuthenticationMode;

#if !SUPPORTS_HOST_ENVIRONMENT
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
#endif

namespace OpenIddict.Client.SystemIntegration;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict client system integration configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientSystemIntegrationConfiguration : IConfigureOptions<OpenIddictClientOptions>,
                                                                     IPostConfigureOptions<OpenIddictClientOptions>,
                                                                     IPostConfigureOptions<OpenIddictClientSystemIntegrationOptions>
{
    private readonly IHostEnvironment _environment;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSystemIntegrationConfiguration"/> class.
    /// </summary>
    /// <param name="environment">The host environment.</param>
    public OpenIddictClientSystemIntegrationConfiguration(IHostEnvironment environment)
        => _environment = environment ?? throw new ArgumentNullException(nameof(environment));

    /// <inheritdoc/>
    public void Configure(OpenIddictClientOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Register the built-in event handlers used by the OpenIddict client system integration components.
        options.Handlers.AddRange(OpenIddictClientSystemIntegrationHandlers.DefaultHandlers);
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictClientOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // If no explicit client URI was set, default to the static "http://localhost/" address, which is
        // adequate for a native/mobile client and points to the embedded web server when it is enabled.
        options.ClientUri ??= new Uri("http://localhost/", UriKind.Absolute);
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictClientSystemIntegrationOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Ensure the operating system is supported.
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Create("android"))     &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.Create("ios"))         &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.Linux)                 &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.Create("maccatalyst")) &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.OSX)                   &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0389));
        }

#if !SUPPORTS_ANDROID
        // When running on Android, iOS, Mac Catalyst or macOS, ensure the version compiled for
        // these platforms is used to prevent the generic/non-OS specific TFM from being used.
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Create("android")))
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0449));
        }
#endif
#if !SUPPORTS_APPKIT
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0449));
        }
#endif
#if !SUPPORTS_UIKIT
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Create("ios")) ||
            RuntimeInformation.IsOSPlatform(OSPlatform.Create("maccatalyst")))
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0449));
        }
#endif

#if SUPPORTS_OPERATING_SYSTEM_VERSIONS_COMPARISON
        // Ensure the operating system version is supported.
        if ((OperatingSystem.IsAndroid()     && !OperatingSystem.IsAndroidVersionAtLeast(21))        ||
            (OperatingSystem.IsIOS()         && !OperatingSystem.IsIOSVersionAtLeast(12))            ||
            (OperatingSystem.IsMacCatalyst() && !OperatingSystem.IsMacCatalystVersionAtLeast(13, 1)) ||
            (OperatingSystem.IsMacOS()       && !OperatingSystem.IsMacOSVersionAtLeast(10, 15))      ||
            (OperatingSystem.IsWindows()     && !OperatingSystem.IsWindowsVersionAtLeast(7)))
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0389));
        }
#else
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !IsWindowsVersionAtLeast(7))
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0389));
        }
#endif

#pragma warning disable CA1416
        // If explicitly set, ensure the specified authentication mode is supported.
        if (options.AuthenticationMode is ASWebAuthenticationSession && !IsASWebAuthenticationSessionSupported())
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0446));
        }

        else if (options.AuthenticationMode is CustomTabsIntent && !IsCustomTabsIntentSupported())
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0452));
        }

        else if (options.AuthenticationMode is WebAuthenticationBroker && !IsWebAuthenticationBrokerSupported())
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0392));
        }
#pragma warning restore CA1416

        // When possible, always prefer OS-managed modes. Otherwise, fall back to the system browser.
        options.AuthenticationMode ??=
            IsASWebAuthenticationSessionSupported() ? ASWebAuthenticationSession :
            IsCustomTabsIntentSupported()           ? CustomTabsIntent           : SystemBrowser;

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Create("android"))     &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.Create("ios"))         &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.Create("maccatalyst")) &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            options.EnableActivationHandling    ??= true;
            options.EnableActivationRedirection ??= true;
            options.EnablePipeServer            ??= true;
            options.EnableEmbeddedWebServer     ??= HttpListener.IsSupported;
        }

        else
        {
            options.EnableActivationHandling    ??= false;
            options.EnableActivationRedirection ??= false;
            options.EnablePipeServer            ??= false;
            options.EnableEmbeddedWebServer     ??= false;
        }

        // If no explicit application discriminator was specified, compute the SHA-256 hash
        // of the application name resolved from the host and use it as a unique identifier.
        if (string.IsNullOrEmpty(options.ApplicationDiscriminator))
        {
            if (string.IsNullOrEmpty(_environment.ApplicationName))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0386));
            }

            var digest = OpenIddictHelpers.ComputeSha256Hash(Encoding.UTF8.GetBytes(_environment.ApplicationName));

            // Note: only the left-most half of the hash is used to limit the length of the resulting discriminator,
            // which is required on platforms like macOS, where the name of pipes is always prefixed with a static part
            // (e.g /var/folders/5j/jjxtct5j1gvg35z6sdh2fz0w0000gn/T/CoreFxPipe_) and must not exceed 104 characters.
            options.ApplicationDiscriminator = Base64UrlEncoder.Encode(digest, 0, digest.Length / 2);
        }

        // If no explicit instance identifier was specified, use a 96-bit random identifier.
        if (string.IsNullOrEmpty(options.InstanceIdentifier))
        {
            options.InstanceIdentifier = Base64UrlEncoder.Encode(OpenIddictHelpers.CreateRandomArray(size: 96));
        }

        // If no explicit pipe name was specified, build one using the application discriminator.
        if (string.IsNullOrEmpty(options.PipeName))
        {
            // Note: on Windows, the name is deliberately prefixed with "LOCAL\" to support
            // partial trust/sandboxed applications that are executed in an AppContainer
            // and cannot communicate with applications outside the sandbox container.
            options.PipeName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ?
                @$"LOCAL\{options.ApplicationDiscriminator}" :
                options.ApplicationDiscriminator;
        }

#if SUPPORTS_CURRENT_USER_ONLY_PIPE_OPTION
        if (options.PipeOptions is null && !RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Note: the CurrentUserOnly option is also supported on Windows, but is less
            // flexible than using a PipeSecurity object (e.g cross-process communication
            // between elevated and non-elevated processes is not possible with this option).
            // As such, it's not used on Windows (instead, an ACL-based PipeSecurity is used).
            options.PipeOptions = PipeOptions.CurrentUserOnly;
        }
#endif

        // Always configure the pipe to use asynchronous operations,
        // even if the flag was not explicitly set by the user.
        options.PipeOptions |= PipeOptions.Asynchronous;

        // On Windows, if no explicit pipe security policy was specified, grant the current
        // user full control over the created pipe and allow cross-process communication
        // between elevated and non-elevated processes. Note: if the process executes
        // inside an AppContainer, don't override the default OS pipe security policy
        // to allow all applications with the same identity to access the named pipe.
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && options.PipeSecurity is null)
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);

            if (!IsWindowsVersionAtLeast(10, 0, 10240) || !HasAppContainerToken(identity))
            {
                options.PipeSecurity = new PipeSecurity();
                options.PipeSecurity.SetOwner(identity.User!);
                options.PipeSecurity.AddAccessRule(new PipeAccessRule(identity.User!,
                    PipeAccessRights.FullControl, AccessControlType.Allow));
            }
        }
    }
}
