/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Validation.DataProtection
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict ASP.NET Core Data Protection configuration is valid.
    /// </summary>
    public class OpenIddictValidationDataProtectionConfiguration : IConfigureOptions<OpenIddictValidationOptions>,
                                                                   IPostConfigureOptions<OpenIddictValidationDataProtectionOptions>
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictValidationDataProtectionConfiguration"/> class.
        /// </summary>
        /// <param name="dataProtectionProvider">The ASP.NET Core Data Protection provider.</param>
        public OpenIddictValidationDataProtectionConfiguration([NotNull] IDataProtectionProvider dataProtectionProvider)
            => _dataProtectionProvider = dataProtectionProvider;

        public void Configure([NotNull] OpenIddictValidationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // Register the built-in event handlers used by the OpenIddict Data Protection validation components.
            options.Handlers.AddRange(OpenIddictValidationDataProtectionHandlers.DefaultHandlers);
        }

        /// <summary>
        /// Populates the default OpenIddict ASP.NET Core Data Protection validation options
        /// and ensures that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The name of the options instance to configure, if applicable.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([CanBeNull] string name, [NotNull] OpenIddictValidationDataProtectionOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            options.DataProtectionProvider ??= _dataProtectionProvider;
        }
    }
}
