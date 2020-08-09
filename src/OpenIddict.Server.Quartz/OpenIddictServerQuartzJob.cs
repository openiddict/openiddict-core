/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Quartz;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.Quartz
{
    /// <summary>
    /// Represents a Quartz.NET job performing scheduled tasks for the OpenIddict server feature.
    /// </summary>
    [DisallowConcurrentExecution]
    public class OpenIddictServerQuartzJob : IJob
    {
        private readonly ILogger _logger;
        private readonly IOptionsMonitor<OpenIddictServerQuartzOptions> _options;
        private readonly IServiceProvider _provider;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictServerQuartzJob"/> class.
        /// </summary>
        public OpenIddictServerQuartzJob() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1081));

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictServerQuartzJob"/> class.
        /// </summary>
        /// <param name="logger">The logger.</param>
        /// <param name="options">The OpenIddict server Quartz.NET options.</param>
        /// <param name="provider">The service provider.</param>
        public OpenIddictServerQuartzJob(
            ILogger<OpenIddictServerQuartzJob> logger,
            IOptionsMonitor<OpenIddictServerQuartzOptions> options,
            IServiceProvider provider)
        {
            _logger = logger;
            _options = options;
            _provider = provider;
        }

        /// <summary>
        /// Gets the default identity assigned to this job.
        /// </summary>
        public static JobKey Identity { get; } = new JobKey(
            name: typeof(OpenIddictServerQuartzJob).Name,
            group: typeof(OpenIddictServerQuartzJob).Assembly.GetName().Name!);

        /// <inheritdoc/>
        public async Task Execute(IJobExecutionContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // TODO: determine whether errors should be swallowed or should be re-thrown to be logged by Quartz.NET.

            // Note: this job is registered as a transient service. As such, it cannot directly depend on scoped services
            // like the core managers. To work around this limitation, a scope is manually created for each invocation.
            var scope = _provider.CreateScope();

            try
            {
                // Note: this background task is responsible of automatically removing orphaned tokens/authorizations
                // (i.e tokens that are no longer valid and ad-hoc authorizations that have no valid tokens associated).
                // Since ad-hoc authorizations and their associated tokens are removed as part of the same operation
                // when they no longer have any token attached, it's more efficient to remove the authorizations first.

                // Note: the authorization/token managers MUST be resolved from the scoped provider
                // as they depend on scoped stores that should be disposed as soon as possible.

                if (!_options.CurrentValue.DisableAuthorizationsPruning)
                {
                    var manager = scope.ServiceProvider.GetService<IOpenIddictAuthorizationManager>();
                    if (manager == null)
                    {
                        // Inform Quartz.NET that the triggers associated with this job should be removed,
                        // as the future invocations will always fail until the application is correctly
                        // re-configured to register the OpenIddict core services in the DI container.
                        throw new JobExecutionException(SR.GetResourceString(SR.ID1277))
                        {
                            UnscheduleAllTriggers = true,
                            UnscheduleFiringTrigger = true,
                            RefireImmediately = false
                        };
                    }

                    try
                    {
                        await manager.PruneAsync(context.CancellationToken);
                    }

                    catch (ConcurrencyException exception)
                    {
                        _logger.LogDebug(exception, SR.GetResourceString(SR.ID7105));
                    }

                    catch (OperationCanceledException exception) when (exception.CancellationToken == context.CancellationToken)
                    {
                        _logger.LogDebug(exception, SR.GetResourceString(SR.ID7107));
                    }

                    catch (Exception exception)
                    {
                        _logger.LogError(exception, SR.GetResourceString(SR.ID7118));
                    }
                }

                if (!_options.CurrentValue.DisableTokensPruning)
                {
                    var manager = scope.ServiceProvider.GetService<IOpenIddictTokenManager>();
                    if (manager == null)
                    {
                        // Inform Quartz.NET that the triggers associated with this job should be removed,
                        // as the future invocations will always fail until the application is correctly
                        // re-configured to register the OpenIddict core services in the DI container.
                        throw new JobExecutionException(SR.GetResourceString(SR.ID1277))
                        {
                            UnscheduleAllTriggers = true,
                            UnscheduleFiringTrigger = true,
                            RefireImmediately = false
                        };
                    }

                    try
                    {
                        await manager.PruneAsync(context.CancellationToken);
                    }

                    catch (ConcurrencyException exception)
                    {
                        _logger.LogDebug(exception, SR.GetResourceString(SR.ID7120));
                    }

                    catch (OperationCanceledException exception) when (exception.CancellationToken == context.CancellationToken)
                    {
                        _logger.LogDebug(exception, SR.GetResourceString(SR.ID7180));
                    }

                    catch (Exception exception)
                    {
                        _logger.LogError(exception, SR.GetResourceString(SR.ID7181));
                    }
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
}
