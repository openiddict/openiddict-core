/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NHibernate;

namespace OpenIddict.NHibernate
{
    /// <summary>
    /// Exposes the NHibernate session used by the OpenIddict stores.
    /// </summary>
    public class OpenIddictNHibernateContext : IOpenIddictNHibernateContext, IDisposable
    {
        private readonly IOptionsMonitor<OpenIddictNHibernateOptions> _options;
        private readonly IServiceProvider _provider;
        private ISession _session;

        public OpenIddictNHibernateContext(
            [NotNull] IOptionsMonitor<OpenIddictNHibernateOptions> options,
            [NotNull] IServiceProvider provider)
        {
            _options = options;
            _provider = provider;
        }

        /// <summary>
        /// Disposes the session held by this instance, if applicable.
        /// </summary>
        public void Dispose() => _session?.Dispose();

        /// <summary>
        /// Gets the <see cref="ISession"/>.
        /// </summary>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the
        /// asynchronous operation, whose result returns the NHibernate session.
        /// </returns>
        /// <remarks>
        /// If a session factory was explicitly set in the OpenIddict NHibernate options,
        /// a new session, specific to the OpenIddict stores is automatically opened
        /// and disposed when the ambient scope is collected. If no session factory
        /// was set, the session is retrieved from the dependency injection container
        /// and a derived instance disabling automatic flush is managed by the context.
        /// </remarks>
        public ValueTask<ISession> GetSessionAsync(CancellationToken cancellationToken)
        {
            if (_session != null)
            {
                return new ValueTask<ISession>(_session);
            }

            if (cancellationToken.IsCancellationRequested)
            {
                return new ValueTask<ISession>(Task.FromCanceled<ISession>(cancellationToken));
            }

            var options = _options.CurrentValue;
            if (options == null)
            {
                throw new InvalidOperationException("The OpenIddict NHibernate options cannot be retrieved.");
            }

            // Note: by default, NHibernate is natively configured to perform automatic flushes
            // on queries when it determines stale data may be returned during their execution.
            // Combined with implicit entity updates, this feature is inconvenient for OpenIddict
            // as it may result in updated entities being persisted before they are explicitly
            // validated by the core managers and marked as updated by the NHibernate stores.
            // To ensure this doesn't interfere with OpenIddict, automatic flush is disabled.

            var factory = options.SessionFactory;
            if (factory == null)
            {
                var session = _provider.GetService<ISession>();
                if (session != null)
                {
                    // If the flush mode is already set to manual, avoid creating a sub-session.
                    // If the session must be derived, all the parameters are inherited from
                    // the original session (except the flush mode, explicitly set to manual).
                    if (session.FlushMode != FlushMode.Manual)
                    {
                        session = _session = session.SessionWithOptions()
                            .AutoClose()
                            .AutoJoinTransaction()
                            .Connection()
                            .ConnectionReleaseMode()
                            .FlushMode(FlushMode.Manual)
                            .Interceptor()
                            .OpenSession();
                    }

                    return new ValueTask<ISession>(session);
                }

                factory = _provider.GetService<ISessionFactory>();
            }

            if (factory == null)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("No suitable NHibernate session or session factory can be found.")
                    .Append("To configure the OpenIddict NHibernate stores to use a specific factory, use ")
                    .Append("'services.AddOpenIddict().AddCore().UseNHibernate().UseSessionFactory()' or register an ")
                    .Append("'ISession'/'ISessionFactory' in the dependency injection container in 'ConfigureServices()'.")
                    .ToString());
            }

            else
            {
                var session = factory.OpenSession();
                session.FlushMode = FlushMode.Manual;

                return new ValueTask<ISession>(_session = session);
            }
        }
    }
}
