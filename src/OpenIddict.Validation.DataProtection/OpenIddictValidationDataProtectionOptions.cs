/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.DataProtection;

namespace OpenIddict.Validation.DataProtection
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict validation handler.
    /// </summary>
    public class OpenIddictValidationDataProtectionOptions
    {
        /// <summary>
        /// Gets or sets the data protection provider used to create the default
        /// data protectors used by the OpenIddict Data Protection validation services.
        /// When this property is set to <c>null</c>, the data protection provider
        /// is directly retrieved from the dependency injection container.
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }

        /// <summary>
        /// Gets or sets the formatter used to read and write Data Protection tokens,
        /// serialized using the same format as the ASP.NET Core authentication tickets.
        /// </summary>
        public IOpenIddictValidationDataProtectionFormatter Formatter { get; set; }
            = new OpenIddictValidationDataProtectionFormatter();
    }
}
