/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Extensions;

namespace OpenIddict.Client.SystemIntegration;

/// <summary>
/// Contains the logic necessary to handle URI protocol activations that
/// are redirected by other instances using inter-process communication.
/// </summary>
/// <remarks>
/// Note: initial URI protocol activations are handled by <see cref="OpenIddictClientSystemIntegrationActivationHandler"/>.
/// </remarks>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictClientSystemIntegrationPipeListener : BackgroundService
{
    private readonly ILogger<OpenIddictClientSystemIntegrationPipeListener> _logger;
    private readonly IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> _options;
    private readonly OpenIddictClientSystemIntegrationService _service;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSystemIntegrationPipeListener"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The OpenIddict client system integration options.</param>
    /// <param name="service">The OpenIddict client system integration service.</param>
    public OpenIddictClientSystemIntegrationPipeListener(
        ILogger<OpenIddictClientSystemIntegrationPipeListener> logger,
        IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> options,
        OpenIddictClientSystemIntegrationService service)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _service = service ?? throw new ArgumentNullException(nameof(service));
    }

    /// <inheritdoc/>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_options.CurrentValue.EnablePipeServer is not true)
        {
            return;
        }

        try
        {
            // Offload the whole process to avoid delaying the initialization of the host.
            await Task.Run(cancellationToken: stoppingToken, function: async () =>
            {
                // Note: while the received load should be minimal, 3 task workers are used
                // to be able to process multiple notifications at the same time, if necessary.
                var tasks = new Task[3];

                for (var index = 0; index < tasks.Length; index++)
                {
                    tasks[index] = ProcessNotificationsAsync(_service, _logger, _options.CurrentValue, stoppingToken);
                }

                // Wait for all the workers to indicate they finished processing incoming notifications.
                await Task.WhenAll(tasks);
            });
        }

        // Ignore exceptions indicating that the host is shutting down and return immediately.
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }

        static async Task ProcessNotificationsAsync(
            OpenIddictClientSystemIntegrationService service, ILogger<OpenIddictClientSystemIntegrationPipeListener> logger,
            OpenIddictClientSystemIntegrationOptions options, CancellationToken cancellationToken)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    using var buffer = new MemoryStream();
                    using var reader = new BinaryReader(buffer);
                    using var stream = CreatePipeServerStream(options);

                    // Wait for a writer to connect to the named pipe.
                    //
                    // Note: NamedPipeServerStream supports cooperative cancellation but it appears that cancellations
                    // are not always properly handled in some obscure circumstances. To ensure the application shutdown
                    // is not delayed by this issue, the Task.WaitAsync(CancellationToken) API is used to stop waiting
                    // for the task returned by WaitForConnectionAsync() to complete when the application shuts down.
                    await stream.WaitForConnectionAsync(cancellationToken).WaitAsync(cancellationToken);

                    // Copy the content to the memory stream asynchronously and rewind it.
                    await stream.CopyToAsync(buffer, bufferSize: 81_920, cancellationToken);
                    buffer.Seek(0L, SeekOrigin.Begin);

                    // Process the inter-process notification based on its declared type.
                    await (reader.ReadInt32() switch
                    {
                        0x01 when ReadProtocolActivation(reader) is var activation
                            => service.HandleProtocolActivationAsync(activation, cancellationToken),

                        var value => throw new InvalidOperationException(SR.FormatID0387(value))
                    });
                }

                // Ignore exceptions indicating that the host is shutting down and return immediately.
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }

                // Swallow other exceptions to ensure the service doesn't exit when encountering an exception.
                catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    logger.LogWarning(exception, SR.GetResourceString(SR.ID6213));

                    continue;
                }
            }
        }

        static NamedPipeServerStream CreatePipeServerStream(OpenIddictClientSystemIntegrationOptions options)
            // Note: the ACL-based PipeSecurity class is only supported on Windows. On other operating systems,
            // PipeOptions.CurrentUserOnly can be used as an alternative, but only for TFMs that implement it.
            => RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ?
#if SUPPORTS_NAMED_PIPE_CONSTRUCTOR_WITH_ACL
                new NamedPipeServerStream(
#elif SUPPORTS_NAMED_PIPE_STATIC_FACTORY_WITH_ACL
                NamedPipeServerStreamAcl.Create(
#else
                NamedPipeServerStreamConstructors.New(
#endif
                    pipeName                  : $@"{options.PipeName}\{options.InstanceIdentifier}",
                    direction                 : PipeDirection.In,
                    maxNumberOfServerInstances: NamedPipeServerStream.MaxAllowedServerInstances,
                    transmissionMode          : PipeTransmissionMode.Byte,
                    options                   : options.PipeOptions.GetValueOrDefault(),
                    inBufferSize              : 0,
                    outBufferSize             : 0,
                    pipeSecurity              : options.PipeSecurity,
                    inheritability            : HandleInheritability.None,
                    additionalAccessRights    : default) :
                new NamedPipeServerStream(
                    pipeName                  : $@"{options.PipeName}\{options.InstanceIdentifier}",
                    direction                 : PipeDirection.In,
                    maxNumberOfServerInstances: NamedPipeServerStream.MaxAllowedServerInstances,
                    transmissionMode          : PipeTransmissionMode.Byte,
                    options                   : options.PipeOptions.GetValueOrDefault(),
                    inBufferSize              : 0,
                    outBufferSize             : 0);

        static OpenIddictClientSystemIntegrationActivation ReadProtocolActivation(BinaryReader reader)
        {
            // Ensure the binary serialization format is supported.
            var version = reader.ReadInt32();
            if (version is not 0x01)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0388));
            }

            var value = reader.ReadString();
            if (string.IsNullOrEmpty(value) || !Uri.TryCreate(value, UriKind.Absolute, out Uri? uri))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0388));
            }

            return new OpenIddictClientSystemIntegrationActivation(uri)
            {
                IsActivationRedirected = true
            };
        }
    }
}
