/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server.DataProtection
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict ASP.NET Core Data Protection configuration is valid.
    /// </summary>
    public class OpenIddictServerDataProtectionConfiguration : IConfigureOptions<OpenIddictServerOptions>,
                                                               IPostConfigureOptions<OpenIddictServerDataProtectionOptions>
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictServerDataProtectionConfiguration"/> class.
        /// </summary>
        /// <param name="dataProtectionProvider">The ASP.NET Core Data Protection provider.</param>
        public OpenIddictServerDataProtectionConfiguration([NotNull] IDataProtectionProvider dataProtectionProvider)
            => _dataProtectionProvider = dataProtectionProvider;

        public void Configure([NotNull] OpenIddictServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // Register the built-in event handlers used by the OpenIddict Data Protection server components.
            foreach (var handler in OpenIddictServerDataProtectionHandlers.DefaultHandlers)
            {
                options.DefaultHandlers.Add(handler);
            }
        }

        /// <summary>
        /// Populates the default OpenIddict ASP.NET Core Data Protection server options
        /// and ensures that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The authentication scheme associated with the handler instance.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([CanBeNull] string name, [NotNull] OpenIddictServerDataProtectionOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            options.DataProtectionProvider ??= _dataProtectionProvider;
        }
    }
}
