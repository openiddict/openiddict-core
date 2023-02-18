/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Extensions;

namespace OpenIddict.Client.SystemIntegration;

/// <summary>
/// Contains the logic necessary to handle HTTP requests.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictClientSystemIntegrationHttpListener : BackgroundService
{
    private readonly TaskCompletionSource<int?> _source = new();
    private readonly ILogger<OpenIddictClientSystemIntegrationHttpListener> _logger;
    private readonly IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> _options;
    private readonly OpenIddictClientSystemIntegrationService _service;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSystemIntegrationHttpListener"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The OpenIddict client system integration options.</param>
    /// <param name="service">The OpenIddict client system integration service.</param>
    public OpenIddictClientSystemIntegrationHttpListener(
        ILogger<OpenIddictClientSystemIntegrationHttpListener> logger,
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
        // Note: the RFC8252 specification recommends starting the web server only when an authorization request is
        // about to be sent and closing it when the response is received. Unfortunately, such an approach has important
        // downsides, as it increases the delay seen by the user before the browser is launched and differs potential
        // server initialization errors. To avoid degrading the user experience, the embedded web server is started in
        // parallel to the host and unsollicted callback requests are always rejected (as they don't include a valid
        // state token). Whenever possible, the HTTP listener is configured to only listen on loopback IP endpoints
        // and rejects unknown requests with an HTTP 404, making attacks targeting the embedded web server unlikely.

        // If the embedded web server instantiation was not enabled, signal the task completion source with a
        // null value to inform the handlers that no HTTP listener is going to be created and return immediately.
        if (_options.CurrentValue.EnableEmbeddedWebServer is not true)
        {
            _source.SetResult(result: null);
            return;
        }

        try
        {
            // Note: finding a free port in the IANA dynamic ports range can take a bit of time on busy systems.
            // To ensure the host initialization is not blocked, the whole process is offloaded to the thread pool.
            await Task.Run(cancellationToken: stoppingToken, function: async () =>
            {
                var (listener, port) = CreateHttpListener(_options.CurrentValue.AllowedEmbeddedWebServerPorts, stoppingToken);
                using (listener)
                {
                    // Inform the handlers that the HTTP listener was created and can
                    // now be accessed via the static port configured in the options
                    // or dynamically chosen at runtime in the IANA dynamic ports range.
                    _source.SetResult(port);

                    // Note: while the received load should be minimal, 3 task workers are used
                    // to be able to process multiple requests at the same time, if necessary.
                    var tasks = new Task[3];

                    for (var index = 0; index < tasks.Length; index++)
                    {
                        tasks[index] = ProcessRequestsAsync(listener, _service, _logger, stoppingToken);
                    }

                    // Wait for all the workers to indicate they finished processing incoming requests.
                    await Task.WhenAll(tasks);
                }
            });
        }

        // Ignore exceptions indicating that the host is shutting down and return immediately.
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }

        static (HttpListener Listener, int Port) CreateHttpListener(List<int> ports, CancellationToken cancellationToken)
        {
            // Note: HttpListener doesn't offer a native way to select a non-busy port from
            // an arbitrary list. To work around this limitation, this local function tries
            // to bind an HttpListener on the first free port in the specified list or in
            // the IANA dynamic ports range if the list doesn't contain any explicit port.
            //
            // For more information, see
            // https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml.

            Stack<Exception>? exceptions = null;

            for (var port = IPEndPoint.MinPort; port <= IPEndPoint.MaxPort; port++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // If one or more explicit ports were specified, ignore ports that are not listed.
                // Otherwise, ignore all the ports outside the IANA dynamic ports range.
                if (ports.Count is 0)
                {
                    if (port < 49152)
                    {
                        continue;
                    }
                }

                else if (!ports.Contains(port))
                {
                    continue;
                }

                var listener = new HttpListener
                {
                    AuthenticationSchemes = AuthenticationSchemes.Anonymous,
                    IgnoreWriteExceptions = true
                };

                // Note: the prefix registration is deliberately not configurable to ensure
                // only loopback authorities are used, which enforces the built-in host header
                // validation performed by HTTP.sys (or the managed .NET implementation on
                // non-Windows operating systems) and doesn't require running the application
                // as an administrator or adding a namespace reservation/ACL rule on Windows.

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // On Windows 10 1511 and higher, listening on 127.0.0.1 and ::1 is preferred
                    // to localhost as it allows ignoring requests that are sent by other machines
                    // located on the same network (even if the firewall is not enabled or not
                    // configured to reject such requests) without requiring administrator rights.
                    //
                    // See https://www.rfc-editor.org/rfc/rfc8252#section-8.3 for more information.
                    if (OpenIddictClientSystemIntegrationHelpers.IsWindowsVersionAtLeast(10, 0, 10586))
                    {
                        if (Socket.OSSupportsIPv4)
                        {
                            listener.Prefixes.Add($"http://{IPAddress.Loopback}:{port.ToString(CultureInfo.InvariantCulture)}/");
                        }

                        if (Socket.OSSupportsIPv6)
                        {
                            listener.Prefixes.Add($"http://[{IPAddress.IPv6Loopback}]:{port.ToString(CultureInfo.InvariantCulture)}/");
                        }
                    }

                    // On older versions, listening on 127.0.0.1 and ::1 requires administrator rights.
                    else
                    {
                        listener.Prefixes.Add($"http://localhost:{port.ToString(CultureInfo.InvariantCulture)}/");
                    }
                }

                else
                {
                    // Note: the managed HttpListener implementation doesn't support IPv6 and
                    // doesn't allow sending a Host header containing the "localhost" authority
                    // when binding on the 127.0.0.1 address. To keep using "localhost" instead of
                    // being forced to use 127.0.0.1, the embedded web server is configured to listen
                    // on "localhost" on platforms that use the managed HttpListener implementation.
                    //
                    // See https://github.com/dotnet/runtime/issues/34399 for more information.
                    listener.Prefixes.Add($"http://localhost:{port.ToString(CultureInfo.InvariantCulture)}/");
                }

                try
                {
                    listener.Start();

                    return (listener, port);
                }

                catch (HttpListenerException exception)
                {
                    listener.Close();

                    exceptions ??= new(capacity: 3);
                    exceptions.Push(new InvalidOperationException(SR.FormatID0384(port), exception));
                }

                catch (Exception exception)
                {
                    listener.Close(); 

                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0391), exception);
                }
            }

            throw exceptions is { Count: > 0 } ?
                new InvalidOperationException(SR.GetResourceString(SR.ID0391), new AggregateException(exceptions.Take(3))) :
                new InvalidOperationException(SR.GetResourceString(SR.ID0391));
        }

        static async Task ProcessRequestsAsync(HttpListener listener, OpenIddictClientSystemIntegrationService service,
            ILogger<OpenIddictClientSystemIntegrationHttpListener> logger, CancellationToken cancellationToken)
        {
            while (listener.IsListening)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    // Note: HttpListener.GetContextAsync() doesn't support cooperative cancellation. To ensure the host
                    // can gracefully shut down without being blocked by an asynchronous call that would never complete,
                    // Task.WaitAsync() is used to stop waiting on the task returned by HttpListener.GetContextAsync()
                    // when the CancellationToken provided by the host indicates that the application is about to shut down.
                    var context = await listener.GetContextAsync().WaitAsync(cancellationToken);

                    using (context.Response)
                    {
                        // Only process requests for which the request URL could be decoded/parsed correctly.
                        if (context.Request.Url is { IsAbsoluteUri: true })
                        {
                            await service.HandleHttpRequestAsync(context, cancellationToken);
                        }
                    }
                }

                // Surface operation canceled exceptions when the host is shutting down.
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }

                // Swallow other exceptions to ensure the worker doesn't exit when encountering an exception.
                catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    logger.LogWarning(exception, SR.GetResourceString(SR.ID6214));

                    continue;
                }
            }
        }
    }

    /// <summary>
    /// Resolves the port associated to the <see cref="HttpListener"/> created by this service, or
    /// <see langword="null"/> if the embedded web server instantiation was disabled in the options.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result
    /// returns the port associated to the <see cref="HttpListener"/> created by this service, or
    /// <see langword="null"/> if the embedded web server instantiation was disabled in the options.
    /// </returns>
    internal Task<int?> GetEmbeddedServerPortAsync(CancellationToken cancellationToken = default)
        => _source.Task.WaitAsync(cancellationToken);
}
