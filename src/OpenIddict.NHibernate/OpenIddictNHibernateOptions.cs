/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using NHibernate;

namespace OpenIddict.NHibernate
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict NHibernate integration.
    /// </summary>
    public class OpenIddictNHibernateOptions
    {
        /// <summary>
        /// Gets or sets the session factory used by the OpenIddict NHibernate stores.
        /// If none is explicitly set, the session factory is resolved from the DI container.
        /// </summary>
        public ISessionFactory SessionFactory { get; set; }
    }
}
