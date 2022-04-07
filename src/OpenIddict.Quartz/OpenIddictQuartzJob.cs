/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Quartz;

/// <summary>
/// Represents a Quartz.NET job performing scheduled tasks for OpenIddict.
/// </summary>
[DisallowConcurrentExecution]
public class OpenIddictQuartzJob : IJob
{
    private readonly IOptionsMonitor<OpenIddictQuartzOptions> _options;
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictQuartzJob"/> class.
    /// </summary>
    public OpenIddictQuartzJob() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0082));

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictQuartzJob"/> class.
    /// </summary>
    /// <param name="options">The OpenIddict Quartz.NET options.</param>
    /// <param name="provider">The service provider.</param>
    public OpenIddictQuartzJob(IOptionsMonitor<OpenIddictQuartzOptions> options!!, IServiceProvider provider!!)
    {
        _options = options;
        _provider = provider;
    }

    /// <summary>
    /// Gets the default identity assigned to this job.
    /// </summary>
    public static JobKey Identity { get; } = new JobKey(
        name: typeof(OpenIddictQuartzJob).Name,
        group: typeof(OpenIddictQuartzJob).Assembly.GetName().Name!);

    /// <inheritdoc/>
    public async Task Execute(IJobExecutionContext context!!)
    {
        List<Exception>? exceptions = null;

        // Note: this job is registered as a transient service. As such, it cannot directly depend on scoped services
        // like the core managers. To work around this limitation, a scope is manually created for each invocation.
        var scope = _provider.CreateScope();

        try
        {
            // Note: this background task is responsible of automatically removing orphaned tokens/authorizations
            // (i.e tokens that are no longer valid and ad-hoc authorizations that have no valid tokens associated).
            // Import: since tokens associated to ad-hoc authorizations are not removed as part of the same operation,
            // the tokens MUST be deleted before removing the ad-hoc authorizations that no longer have any token.

            if (!_options.CurrentValue.DisableTokenPruning)
            {
                var manager = scope.ServiceProvider.GetService<IOpenIddictTokenManager>();
                if (manager is null)
                {
                    // Inform Quartz.NET that the triggers associated with this job should be removed,
                    // as the future invocations will always fail until the application is correctly
                    // re-configured to register the OpenIddict core services in the DI container.
                    throw new JobExecutionException(new InvalidOperationException(SR.GetResourceString(SR.ID0278)))
                    {
                        RefireImmediately = false,
                        UnscheduleAllTriggers = true,
                        UnscheduleFiringTrigger = true
                    };
                }

                var threshold = DateTimeOffset.UtcNow - _options.CurrentValue.MinimumTokenLifespan;

                try
                {
                    await manager.PruneAsync(threshold, context.CancellationToken);
                }

                // OutOfMemoryExceptions are treated as fatal errors and are always re-thrown as-is.
                catch (OutOfMemoryException)
                {
                    throw;
                }

                // OperationCanceledExceptions are typically thrown when the host is about to shut down.
                // To allow the host to shut down as fast as possible, this exception type is special-cased
                // to prevent further processing in this job and inform Quartz.NET it shouldn't be refired.
                catch (OperationCanceledException exception) when (exception.CancellationToken == context.CancellationToken)
                {
                    throw new JobExecutionException(exception)
                    {
                        RefireImmediately = false
                    };
                }

                // AggregateExceptions are generally thrown by the manager itself when one or multiple exception(s)
                // occurred while trying to prune the entities. In this case, add the inner exceptions to the collection.
                catch (AggregateException exception)
                {
                    exceptions ??= new List<Exception>(capacity: exception.InnerExceptions.Count);
                    exceptions.AddRange(exception.InnerExceptions);
                }

                // Other exceptions are assumed to be transient and are added to the exceptions collection
                // to be re-thrown later (typically, at the very end of this job, as an AggregateException).
                catch (Exception exception)
                {
                    exceptions ??= new List<Exception>(capacity: 1);
                    exceptions.Add(exception);
                }
            }

            if (!_options.CurrentValue.DisableAuthorizationPruning)
            {
                var manager = scope.ServiceProvider.GetService<IOpenIddictAuthorizationManager>();
                if (manager is null)
                {
                    // Inform Quartz.NET that the triggers associated with this job should be removed,
                    // as the future invocations will always fail until the application is correctly
                    // re-configured to register the OpenIddict core services in the DI container.
                    throw new JobExecutionException(new InvalidOperationException(SR.GetResourceString(SR.ID0278)))
                    {
                        RefireImmediately = false,
                        UnscheduleAllTriggers = true,
                        UnscheduleFiringTrigger = true
                    };
                }

                var threshold = DateTimeOffset.UtcNow - _options.CurrentValue.MinimumAuthorizationLifespan;

                try
                {
                    await manager.PruneAsync(threshold, context.CancellationToken);
                }

                // OutOfMemoryExceptions are treated as fatal errors and are always re-thrown as-is.
                catch (OutOfMemoryException)
                {
                    throw;
                }

                // OperationCanceledExceptions are typically thrown when the host is about to shut down.
                // To allow the host to shut down as fast as possible, this exception type is special-cased
                // to prevent further processing in this job and inform Quartz.NET it shouldn't be refired.
                catch (OperationCanceledException exception) when (exception.CancellationToken == context.CancellationToken)
                {
                    throw new JobExecutionException(exception)
                    {
                        RefireImmediately = false
                    };
                }

                // AggregateExceptions are generally thrown by the manager itself when one or multiple exception(s)
                // occurred while trying to prune the entities. In this case, add the inner exceptions to the collection.
                catch (AggregateException exception)
                {
                    exceptions ??= new List<Exception>(capacity: exception.InnerExceptions.Count);
                    exceptions.AddRange(exception.InnerExceptions);
                }

                // Other exceptions are assumed to be transient and are added to the exceptions collection
                // to be re-thrown later (typically, at the very end of this job, as an AggregateException).
                catch (Exception exception)
                {
                    exceptions ??= new List<Exception>(capacity: 1);
                    exceptions.Add(exception);
                }
            }

            if (exceptions is not null)
            {
                throw new JobExecutionException(new AggregateException(exceptions))
                {
                    // Only refire the job if the maximum refire count set in the options wasn't reached.
                    RefireImmediately = context.RefireCount < _options.CurrentValue.MaximumRefireCount
                };
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
