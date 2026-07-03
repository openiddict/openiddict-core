/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Text;
using System.ComponentModel;
using System.IO.Pipes;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using static OpenIddict.Client.SystemIntegration.OpenIddictClientSystemIntegrationAuthenticationMode;

namespace OpenIddict.Client.SystemIntegration;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict client system integration configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientSystemIntegrationConfiguration : IConfigureOptions<OpenIddictClientOptions>,
                                                                     IPostConfigureOptions<OpenIddictClientOptions>,
                                                                     IPostConfigureOptions<OpenIddictClientSystemIntegrationOptions>,
                                                                     IValidateOptions<OpenIddictClientSystemIntegrationOptions>
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSystemIntegrationConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictClientSystemIntegrationConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void Configure(OpenIddictClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Register the built-in event handlers used by the OpenIddict client system integration components.
        options.Handlers.AddRange(OpenIddictClientSystemIntegrationHandlers.DefaultHandlers);

        // Enable response_mode=fragment support by default.
        options.ResponseModes.Add(ResponseModes.Fragment);
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // If no explicit client URI was set, default to the static "http://localhost/" address, which is
        // adequate for a native/mobile client and points to the embedded web server when it is enabled.
        options.ClientUri ??= new Uri("http://localhost/", UriKind.Absolute);
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictClientSystemIntegrationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // When possible, always prefer OS-managed modes. Otherwise, fall back to the system browser.
        options.AuthenticationMode ??=
            IsASWebAuthenticationSessionSupported() ? ASWebAuthenticationSession :
            IsCustomTabsIntentSupported()           ? CustomTabsIntent           : SystemBrowser;

        if (!OperatingSystem.IsAndroid()     && !OperatingSystem.IsIOS() &&
            !OperatingSystem.IsMacCatalyst() && !OperatingSystem.IsMacOS())
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

        // If no explicit application discriminator was specified, compute the SHA-256 hash of the application
        // name resolved from the host environment (if available) and use it as a unique identifier.
        if (string.IsNullOrEmpty(options.ApplicationDiscriminator) &&
            _provider.GetService<IHostEnvironment>() is IHostEnvironment { ApplicationName.Length: > 0 } environment)
        {
            var digest = SHA256.HashData(Encoding.UTF8.GetBytes(environment.ApplicationName));

            // Note: only the left-most half of the hash is used to limit the length of the resulting discriminator,
            // which is required on platforms like macOS, where the name of pipes is always prefixed with a static part
            // (e.g /var/folders/5j/jjxtct5j1gvg35z6sdh2fz0w0000gn/T/CoreFxPipe_) and must not exceed 104 characters.
            options.ApplicationDiscriminator = Base64Url.EncodeToString(digest.AsSpan(0, digest.Length / 2));
        }

        // If no explicit instance identifier was specified, use a 96-bit random identifier.
        if (string.IsNullOrEmpty(options.InstanceIdentifier))
        {
            options.InstanceIdentifier = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(count: 96 / 8));
        }

        // If no explicit pipe name was specified, build one using the application discriminator.
        if (string.IsNullOrEmpty(options.PipeName) && !string.IsNullOrEmpty(options.ApplicationDiscriminator))
        {
            // Note: on Windows, the name is deliberately prefixed with "LOCAL\" to support
            // partial trust/sandboxed applications that are executed in an AppContainer
            // and cannot communicate with applications outside the sandbox container.
            options.PipeName = OperatingSystem.IsWindows() ?
                @$"LOCAL\{options.ApplicationDiscriminator}" :
                options.ApplicationDiscriminator;
        }

#if NET
        if (options.PipeOptions is null && !OperatingSystem.IsWindows())
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
        if (OperatingSystem.IsWindows() && options.PipeSecurity is null)
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);

            if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 10240) || !HasAppContainerToken(identity))
            {
                options.PipeSecurity = new PipeSecurity();
                options.PipeSecurity.SetOwner(identity.User!);
                options.PipeSecurity.AddAccessRule(new PipeAccessRule(identity.User!,
                    PipeAccessRights.FullControl, AccessControlType.Allow));
            }
        }
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, OpenIddictClientSystemIntegrationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var builder = new ValidateOptionsResultBuilder();

        // Ensure the operating system version is supported.
        if (!OperatingSystem.IsAndroidVersionAtLeast(21)   && !OperatingSystem.IsIOSVersionAtLeast(12) &&
            !OperatingSystem.IsLinux()                     && !OperatingSystem.IsMacCatalystVersionAtLeast(13, 1) &&
            !OperatingSystem.IsMacOSVersionAtLeast(10, 15) && !OperatingSystem.IsWindowsVersionAtLeast(7))
        {
            builder.AddError(SR.GetResourceString(SR.ID0389));
        }

#if !ANDROID
        // When running on Android, iOS or Mac Catalyst, ensure the version compiled for these platforms
        // is used to prevent the generic/non-OS specific TFM from being used as launching the system
        // browser cannot be done using Process.Start() and requires using OS-specific APIs that are
        // not available on the portable version of the OpenIddict.Client.SystemIntegration package.
        if (OperatingSystem.IsAndroid())
        {
            builder.AddError(SR.GetResourceString(SR.ID0449));
        }
#endif

#if !IOS && !MACCATALYST
        else if (OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
        {
            builder.AddError(SR.GetResourceString(SR.ID0449));
        }
#endif

#pragma warning disable CA1416
        // If explicitly set, ensure the specified authentication mode is supported.
        if (options.AuthenticationMode is ASWebAuthenticationSession && !IsASWebAuthenticationSessionSupported())
        {
            builder.AddError(SR.GetResourceString(SR.ID0446));
        }

        else if (options.AuthenticationMode is CustomTabsIntent && !IsCustomTabsIntentSupported())
        {
            builder.AddError(SR.GetResourceString(SR.ID0452));
        }

        else if (options.AuthenticationMode is WebAuthenticationBroker && !IsWebAuthenticationBrokerSupported())
        {
            builder.AddError(SR.GetResourceString(SR.ID0392));
        }
#pragma warning restore CA1416

        // If activation redirection or the pipe server is enabled, ensure a pipe name
        // was specified or could be inferred from the application discriminator.
        if (string.IsNullOrEmpty(options.PipeName) &&
           (options.EnableActivationRedirection is true || options.EnablePipeServer is true))
        {
            builder.AddError(SR.GetResourceString(SR.ID0386));
        }

        return builder.Build();
    }
}
