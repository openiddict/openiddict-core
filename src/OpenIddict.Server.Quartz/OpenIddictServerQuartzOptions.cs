/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.Quartz
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict Quartz.NET server integration.
    /// </summary>
    public class OpenIddictServerQuartzOptions
    {
        /// <summary>
        /// Gets or sets a boolean indicating whether authorizations pruning should be disabled.
        /// </summary>
        public bool DisableAuthorizationsPruning { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether tokens pruning should be disabled.
        /// </summary>
        public bool DisableTokensPruning { get; set; }
    }
}
