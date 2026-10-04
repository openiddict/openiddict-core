/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Core;

/// <summary>
/// Represents a hosted service performing background tasks for OpenIddict.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictCoreBackgroundService : BackgroundService
{
    private readonly ILogger<OpenIddictCoreBackgroundService> _logger;
    private readonly IOptionsMonitor<OpenIddictCoreOptions> _options;
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictCoreBackgroundService"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The OpenIddict core options.</param>
    /// <param name="provider">The service provider.</param>
    public OpenIddictCoreBackgroundService(
        ILogger<OpenIddictCoreBackgroundService> logger,
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IServiceProvider provider)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <inheritdoc/>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var options = _options.CurrentValue;

        // Note: if all the automatic pruning features are disabled, the background service no-ops.
        if (options.DisableAutomaticAuthorizationPruning &&
            options.DisableAutomaticSessionPruning && options.DisableAutomaticTokenPruning)
        {
            return;
        }

        // Note: an initialization delay is used to avoid executing the pruning logic immediately after
        // the application starts and to reduce the risk of multiple instances of the application
        // pruning the database at the same time (which could lead to deadlocks in some cases).
#if NET
        await Task.Delay(TimeSpan.FromMinutes(Random.Shared.Next(1, 10)), options.TimeProvider, stoppingToken);
#else
        await options.TimeProvider.Delay(TimeSpan.FromMinutes(Random.Shared.Next(1, 10)), stoppingToken);
#endif

        using var timer = new PeriodicTimer(TimeSpan.FromHours(1), options.TimeProvider);

        // Note: exceptions thrown by the pruning logic are caught and logged to avoid crashing
        // the background service and to ensure these exceptions are not propagated to the
        // .NET Generic Host (which would cause the application to be stopped by default).

        do
        {
            await using var scope = _provider.CreateAsyncScope();

            // Important: since authorizations that still have tokens attached are never
            // pruned, the tokens MUST be deleted before deleting the authorizations.

            if (!options.DisableAutomaticTokenPruning)
            {
                var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
                var threshold = options.TimeProvider.GetUtcNow() - options.MinimumTokenLifespan;

                try
                {
                    await manager.PruneAsync(threshold, stoppingToken);
                }

                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }

                catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    _logger.LogInformation(6298, exception, SR.GetResourceString(SR.ID6298));
                }
            }

            if (!options.DisableAutomaticAuthorizationPruning)
            {
                var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
                var threshold = options.TimeProvider.GetUtcNow() - options.MinimumAuthorizationLifespan;

                try
                {
                    await manager.PruneAsync(threshold, stoppingToken);
                }

                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }

                catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    _logger.LogInformation(6299, exception, SR.GetResourceString(SR.ID6299));
                }
            }

            // Important: since sessions that still have tokens attached are never
            // pruned, the tokens MUST be deleted before deleting the sessions.

            if (!options.DisableAutomaticSessionPruning)
            {
                var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictSessionManager>();
                var threshold = options.TimeProvider.GetUtcNow() - options.MinimumSessionLifespan;

                try
                {
                    await manager.PruneAsync(threshold, stoppingToken);
                }

                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }

                catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    _logger.LogInformation(6300, exception, SR.GetResourceString(SR.ID6300));
                }
            }
        }

        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
