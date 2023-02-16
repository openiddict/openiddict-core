/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.SystemIntegration;

/// <summary>
/// Contains the logic necessary to handle initial URI protocol activations.
/// </summary>
/// <remarks>
/// Note: redirected URI protocol activations are handled by <see cref="OpenIddictClientSystemIntegrationPipeListener"/>.
/// </remarks>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictClientSystemIntegrationActivationHandler : IHostedService
{
    private readonly IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> _options;
    private readonly OpenIddictClientSystemIntegrationService _service;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSystemIntegrationActivationHandler"/> class.
    /// </summary>
    /// <param name="options">The OpenIddict client system integration integration options.</param>
    /// <param name="service">The OpenIddict client system integration service.</param>
    public OpenIddictClientSystemIntegrationActivationHandler(
        IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> options,
        OpenIddictClientSystemIntegrationService service)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _service = service ?? throw new ArgumentNullException(nameof(service));
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // Note: initial URI protocol activation handling is implemented as a regular IHostedService
        // rather than as a BackgroundService to allow blocking the initialization of the host until
        // the activation is fully processed by the OpenIddict pipeline. By doing that, the UI thread
        // is not started until redirection requests (like authorization responses) are fully processed,
        // which allows handling these requests transparently and helps avoid the "flashing window effect":
        // once a request has been handled by the OpenIddict pipeline, a dedicated handler is responsible
        // for stopping the application gracefully using the IHostApplicationLifetime.StopApplication() API.

        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled(cancellationToken);
        }

        // If the protocol activation processing logic was not enabled, ignore the activation.
        if (_options.CurrentValue.EnableActivationHandling is not true)
        {
            return Task.CompletedTask;
        }

        // Determine whether the current instance is initialized to react to a protocol activation.
        // If it's not, return immediately to avoid adding latency to the application startup process.
        if (GetProtocolActivation() is not OpenIddictClientSystemIntegrationActivation activation)
        {
            return Task.CompletedTask;
        }

        return _service.HandleProtocolActivationAsync(activation, cancellationToken);

        [MethodImpl(MethodImplOptions.NoInlining)]
        static OpenIddictClientSystemIntegrationActivation? GetProtocolActivation()
        {
#if SUPPORTS_WINDOWS_RUNTIME
            // On platforms that support WinRT, always favor the AppInstance.GetActivatedEventArgs() API.
            if (OpenIddictClientSystemIntegrationHelpers.IsWindowsRuntimeSupported() &&
                OpenIddictClientSystemIntegrationHelpers.GetProtocolActivationUriWithWindowsRuntime() is Uri uri)
            {
                return new OpenIddictClientSystemIntegrationActivation(uri);
            }
#endif
            // Otherwise, try to extract the protocol activation from the command line arguments.
            if (OpenIddictClientSystemIntegrationHelpers.GetProtocolActivationUriFromCommandLineArguments(
                Environment.GetCommandLineArgs()) is Uri value)
            {
                return new OpenIddictClientSystemIntegrationActivation(value);
            }

            return null;
        }
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
