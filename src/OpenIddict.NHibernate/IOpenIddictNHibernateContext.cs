/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading;
using System.Threading.Tasks;
using NHibernate;

namespace OpenIddict.NHibernate
{
    /// <summary>
    /// Exposes the NHibernate session used by the OpenIddict stores.
    /// </summary>
    public interface IOpenIddictNHibernateContext
    {
        /// <summary>
        /// Gets the <see cref="ISession"/>.
        /// </summary>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the
        /// asynchronous operation, whose result returns the NHibernate session.
        /// </returns>
        ValueTask<ISession> GetSessionAsync(CancellationToken cancellationToken);
    }
}
