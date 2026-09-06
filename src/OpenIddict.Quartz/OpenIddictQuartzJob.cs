/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Quartz;

/// <summary>
/// Represents a Quartz.NET job performing scheduled tasks for OpenIddict.
/// </summary>
[DisallowConcurrentExecution, EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictQuartzJob : IJob
{
    private readonly IServiceProvider _provider;

#if !NET10_0_OR_GREATER
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictQuartzJob"/> class.
    /// </summary>
    public OpenIddictQuartzJob() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0082));
#endif

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictQuartzJob"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictQuartzJob(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <summary>
    /// Gets the default identity assigned to this job.
    /// </summary>
    public static JobKey Identity { get; } = new JobKey(
        name: SR.GetResourceString(SR.ID8003),
        group: SR.GetResourceString(SR.ID8005));

    /// <inheritdoc/>
#if NET10_0_OR_GREATER
    public async ValueTask Execute(IJobExecutionContext context, CancellationToken cancellationToken = default)
#else
    public async Task Execute(IJobExecutionContext context)
#endif
    {
        ArgumentNullException.ThrowIfNull(context);

        List<Exception>? exceptions = null;

        await using var scope = _provider.CreateAsyncScope();

        var options = scope.ServiceProvider.GetRequiredService<IOptionsMonitor<OpenIddictQuartzOptions>>().CurrentValue;

        // Important: since authorizations that still have tokens attached are never
        // pruned, the tokens MUST be deleted before deleting the authorizations.

        if (!options.DisableTokenPruning)
        {
            var manager = scope.ServiceProvider.GetService<IOpenIddictTokenManager>() ??
                throw new JobExecutionException(new InvalidOperationException(SR.GetResourceString(SR.ID0278)))
                {
                    RefireImmediately = false,
                    UnscheduleAllTriggers = true,
                    UnscheduleFiringTrigger = true
                };

            var threshold = options.TimeProvider.GetUtcNow() - options.MinimumTokenLifespan;

            try
            {
                await manager.PruneAsync(threshold, context.CancellationToken);
            }

            // OperationCanceledExceptions are typically thrown when the host is about to shut down.
            // To allow the host to shut down as fast as possible, this exception type is special-cased
            // to prevent further processing in this job and inform Quartz.NET it shouldn't be refired.
            catch (OperationCanceledException exception) when (context.CancellationToken.IsCancellationRequested)
            {
                throw new JobExecutionException(exception)
                {
                    RefireImmediately = false
                };
            }

            // AggregateExceptions are generally thrown by the manager itself when one or multiple exception(s)
            // occurred while trying to prune the entities. In this case, add the inner exceptions to the collection.
            catch (AggregateException exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                exceptions ??= new List<Exception>(capacity: exception.InnerExceptions.Count);
                exceptions.AddRange(exception.InnerExceptions);
            }

            // Other non-fatal exceptions are assumed to be transient and are added to the exceptions collection
            // to be re-thrown later (typically, at the very end of this job, as an AggregateException).
            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                exceptions ??= new List<Exception>(capacity: 1);
                exceptions.Add(exception);
            }
        }

        if (!options.DisableAuthorizationPruning)
        {
            var manager = scope.ServiceProvider.GetService<IOpenIddictAuthorizationManager>() ??
                throw new JobExecutionException(new InvalidOperationException(SR.GetResourceString(SR.ID0278)))
                {
                    RefireImmediately = false,
                    UnscheduleAllTriggers = true,
                    UnscheduleFiringTrigger = true
                };

            var threshold = options.TimeProvider.GetUtcNow() - options.MinimumAuthorizationLifespan;

            try
            {
                await manager.PruneAsync(threshold, context.CancellationToken);
            }

            // OperationCanceledExceptions are typically thrown when the host is about to shut down.
            // To allow the host to shut down as fast as possible, this exception type is special-cased
            // to prevent further processing in this job and inform Quartz.NET it shouldn't be refired.
            catch (OperationCanceledException exception) when (context.CancellationToken.IsCancellationRequested)
            {
                throw new JobExecutionException(exception)
                {
                    RefireImmediately = false
                };
            }

            // AggregateExceptions are generally thrown by the manager itself when one or multiple exception(s)
            // occurred while trying to prune the entities. In this case, add the inner exceptions to the collection.
            catch (AggregateException exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                exceptions ??= new List<Exception>(capacity: exception.InnerExceptions.Count);
                exceptions.AddRange(exception.InnerExceptions);
            }

            // Other non-fatal exceptions are assumed to be transient and are added to the exceptions collection
            // to be re-thrown later (typically, at the very end of this job, as an AggregateException).
            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                exceptions ??= new List<Exception>(capacity: 1);
                exceptions.Add(exception);
            }
        }

        if (exceptions is { Count: > 0 })
        {
            throw new JobExecutionException(new AggregateException(exceptions))
            {
                // Only refire the job if the maximum refire count set in the options wasn't reached.
                RefireImmediately = context.RefireCount < options.MaximumRefireCount
            };
        }
    }
}
