/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;

namespace OpenIddict.Core
{
    public class OpenIddictCoreOptions
    {
        /// <summary>
        /// Gets or sets the type corresponding to the default Application entity,
        /// used by the non-generic application manager and the server/validation services.
        /// </summary>
        public Type DefaultApplicationType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the default Authorization entity,
        /// used by the non-generic authorization manager and the server/validation services.
        /// </summary>
        public Type DefaultAuthorizationType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the default Scope entity,
        /// used by the non-generic scope manager and the server/validation services.
        /// </summary>
        public Type DefaultScopeType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the default Token entity,
        /// used by the non-generic token manager and the server/validation services.
        /// </summary>
        public Type DefaultTokenType { get; set; }
    }
}