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
        /// Gets or sets the type corresponding to the Application entity.
        /// </summary>
        public Type DefaultApplicationType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the Authorization entity.
        /// </summary>
        public Type DefaultAuthorizationType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the Scope entity.
        /// </summary>
        public Type DefaultScopeType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the Token entity.
        /// </summary>
        public Type DefaultTokenType { get; set; }
    }
}