/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.DataProtection;

namespace OpenIddict.Server.DataProtection
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict server handler.
    /// </summary>
    public class OpenIddictServerDataProtectionOptions
    {
        /// <summary>
        /// Gets or sets the data protection provider used to create the default
        /// data protectors used by the OpenIddict Data Protection server services.
        /// When this property is set to <c>null</c>, the data protection provider
        /// is directly retrieved from the dependency injection container.
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }

        /// <summary>
        /// Gets or sets the formatter used to read and write Data Protection tokens,
        /// serialized using the same format as the ASP.NET Core authentication tickets.
        /// </summary>
        public IOpenIddictServerDataProtectionFormatter Formatter { get; set; }
            = new OpenIddictServerDataProtectionFormatter();

        /// <summary>
        /// Gets or sets a boolean indicating whether the default token format
        /// should be preferred when issuing new access tokens, refresh tokens
        /// and authorization codes. This property is set to <c>false</c> by default.
        /// </summary>
        public bool PreferDefaultTokenFormat { get; set; }
    }
}
