/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using MongoDB.Driver;

namespace OpenIddict.MongoDb
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict MongoDB integration.
    /// </summary>
    public class OpenIddictMongoDbOptions
    {
        /// <summary>
        /// Gets or sets the name of the applications collection (by default, openiddict.applications).
        /// </summary>
        public string ApplicationsCollectionName { get; set; } = "openiddict.applications";

        /// <summary>
        /// Gets or sets the name of the authorizations collection (by default, openiddict.authorizations).
        /// </summary>
        public string AuthorizationsCollectionName { get; set; } = "openiddict.authorizations";

        /// <summary>
        /// Gets or sets the <see cref="IMongoDatabase"/> used by the OpenIddict stores.
        /// If no value is explicitly set, the database is resolved from the DI container.
        /// </summary>
        public IMongoDatabase Database { get; set; }

        /// <summary>
        /// Gets or sets the name of the scopes collection (by default, openiddict.scopes).
        /// </summary>
        public string ScopesCollectionName { get; set; } = "openiddict.scopes";

        /// <summary>
        /// Gets or sets the name of the tokens collection (by default, openiddict.tokens).
        /// </summary>
        public string TokensCollectionName { get; set; } = "openiddict.tokens";
    }
}
