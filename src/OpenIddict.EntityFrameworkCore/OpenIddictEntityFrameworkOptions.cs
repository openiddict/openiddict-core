/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.EntityFrameworkCore
{
    /// <summary>
    /// Custom options for Entity Framework.
    /// </summary>
    public class OpenIddictEntityFrameworkOptions
    {
        public OpenIddictEntityFrameworkOptions()
        {
            ApplicationsTableName = "OpenIddictApplications";
            AuthorizationsTableName = "OpenIddictAuthorizations";
            ScopesTableName = "OpenIddictScopes";
            TokensTableName = "OpenIddictTokens";
        }

        /// <summary>
        /// Custom table name for OpenIddictApplication entity.
        /// </summary>
        public string ApplicationsTableName { get; set; }

        /// <summary>
        /// Custom table name for OpenIddictAuthorization entity.
        /// </summary>
        public string AuthorizationsTableName { get; set; }

        /// <summary>
        /// Custom table name for OpenIddictScope entity.
        /// </summary>
        public string ScopesTableName { get; set; }

        /// <summary>
        /// Custom table name for OpenIddictToken entity.
        /// </summary>
        public string TokensTableName { get; set; }
    }
}