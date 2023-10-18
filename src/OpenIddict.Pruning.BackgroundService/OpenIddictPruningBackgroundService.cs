/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Extensions;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Pruning.BackgroundService;

/// <summary>
/// Represents a Pruning job performing scheduled tasks for OpenIddict.
/// </summary>
public sealed class OpenIddictPruningBackgroundService : Microsoft.Extensions.Hosting.BackgroundService
{
    private readonly IOptionsMonitor<OpenIddictPruningOptions> _options;
    private readonly IServiceProvider _provider;
    private readonly ILogger<OpenIddictPruningBackgroundService> _logger;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictPruningBackgroundService"/> class.
    /// </summary>
    /// <param name="options">The OpenIddict Pruning options.</param>
    /// <param name="provider">The service provider.</param>
    /// <param name="logger">Logger</param>
    public OpenIddictPruningBackgroundService(IOptionsMonitor<OpenIddictPruningOptions> options, IServiceProvider provider, ILogger<OpenIddictPruningBackgroundService> logger)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
           await Task.Delay(_options.CurrentValue.FirstRun, stoppingToken);
        }
        catch
        {
           //any exception here is a cancellation of the job
           return;
        }

        while (stoppingToken.IsCancellationRequested == false)
        {
           try
           {
              await PruneAsync(stoppingToken);
           }
           catch (InvalidOperationException)
           {
              throw;
           }
           catch (Exception e)
           {
              _logger.LogError(e, "Error while pruning");
           }
           try
           {
              await Task.Delay(_options.CurrentValue.Interval, stoppingToken);
           }
           catch
           {
              //any exception here is a cancellation of the job
              return;
           }
        }
    }

    /// <summary>
    /// Prune tokens and authorizations.
    /// </summary>
    /// <param name="cancellationToken">CancellationToken</param>
    /// <exception cref="InvalidOperationException">Thrown if configuration is wrong</exception>
    /// <exception cref="AggregateException">Thrown for all other exceptions</exception>
    public async Task PruneAsync(CancellationToken cancellationToken)
    {
       List<Exception>? exceptions = null;

       // Note: this job is registered as a transient service. As such, it cannot directly depend on scoped services
       // like the core managers. To work around this limitation, a scope is manually created for each invocation.
       var scope = _provider.CreateScope();

       try
       {
          // Note: this background task is responsible for automatically removing orphaned tokens/authorizations
          // (i.e tokens that are no longer valid and ad-hoc authorizations that have no valid tokens associated).
          // Import: since tokens associated to ad-hoc authorizations are not removed as part of the same operation,
          // the tokens MUST be deleted before removing the ad-hoc authorizations that no longer have any token.

          var options = _options.CurrentValue;
          if (!options.DisableTokenPruning)
          {
             var manager = scope.ServiceProvider.GetService<IOpenIddictTokenManager>();
             if (manager is null)
             {
                // Inform Pruning.NET that the triggers associated with this job should be removed,
                // as the future invocations will always fail until the application is correctly
                // re-configured to register the OpenIddict core services in the DI container.
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0278));
             }

             var threshold = DateTimeOffset.UtcNow - options.MinimumTokenLifespan;
             try
             {
                await manager.PruneAsync(threshold, cancellationToken);
             }

             // OperationCanceledExceptions are typically thrown when the host is about to shut down.
             // To allow the host to shut down as fast as possible, this exception type is special-cased
             // to prevent further processing in this job.
             catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
             {
                return;
             }

             // AggregateExceptions are generally thrown by the manager itself when one or multiple exception(s)
             // occurred while trying to prune the entities. In this case, add the inner exceptions to the collection.
             catch (AggregateException exception) when (!OpenIddictHelpers.IsFatal(exception))
             {
                exceptions = new List<Exception>(exception.InnerExceptions);
             }

             // Other non-fatal exceptions are assumed to be transient and are added to the exceptions collection
             // to be re-thrown later (typically, at the very end of this job, as an AggregateException).
             catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
             {
                exceptions = new List<Exception> { exception };
             }
          }

          if (!options.DisableAuthorizationPruning)
          {
             var manager = scope.ServiceProvider.GetService<IOpenIddictAuthorizationManager>();
             if (manager is null)
             {
                // Inform Pruning.NET that the triggers associated with this job should be removed,
                // as the future invocations will always fail until the application is correctly
                // re-configured to register the OpenIddict core services in the DI container.
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0278));
             }

             var threshold = DateTimeOffset.UtcNow - options.MinimumAuthorizationLifespan;

             try
             {
                await manager.PruneAsync(threshold, cancellationToken);
             }

             // OperationCanceledExceptions are typically thrown when the host is about to shut down.
             // To allow the host to shut down as fast as possible, this exception type is special-cased
             // to prevent further processing in this job.
             catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
             {
                return;
             }

             // AggregateExceptions are generally thrown by the manager itself when one or multiple exception(s)
             // occurred while trying to prune the entities. In this case, add the inner exceptions to the collection.
             catch (AggregateException exception) when (!OpenIddictHelpers.IsFatal(exception))
             {
                exceptions = new List<Exception>(exception.InnerExceptions);
             }

             // Other non-fatal exceptions are assumed to be transient and are added to the exceptions collection
             // to be re-thrown later (typically, at the very end of this job, as an AggregateException).
             catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
             {
                exceptions = new List<Exception> { exception };
             }
          }

          if (exceptions is not null)
          {
             throw new AggregateException(exceptions);
          }
       }

       finally
       {
          if (scope is IAsyncDisposable disposable)
          {
             await disposable.DisposeAsync();
          }

          else
          {
             scope.Dispose();
          }
       }
    }
}
