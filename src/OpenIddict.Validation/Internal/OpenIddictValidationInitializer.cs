/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Text;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Contains the methods required to ensure that the configuration used by
    /// the OpenIddict validation handler is in a consistent and valid state.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictValidationInitializer : IPostConfigureOptions<OpenIddictValidationOptions>
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictValidationInitializer"/> class.
        /// </summary>
        public OpenIddictValidationInitializer([NotNull] IDataProtectionProvider dataProtectionProvider)
        {
            _dataProtectionProvider = dataProtectionProvider;
        }

        /// <summary>
        /// Populates the default OpenIddict validation options and ensure
        /// that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The authentication scheme associated with the handler instance.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([NotNull] string name, [NotNull] OpenIddictValidationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The options instance name cannot be null or empty.", nameof(name));
            }

            if (options.EventsType == null || options.EventsType != typeof(OpenIddictValidationProvider))
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("OpenIddict can only be used with its built-in validation provider.")
                    .AppendLine("This error may indicate that 'OpenIddictValidationOptions.EventsType' was manually set.")
                    .Append("To execute custom request handling logic, consider registering an event handler using ")
                    .Append("the generic 'services.AddOpenIddict().AddValidation().AddEventHandler()' method.")
                    .ToString());
            }

            if (options.DataProtectionProvider == null)
            {
                options.DataProtectionProvider = _dataProtectionProvider;
            }

            if (options.UseReferenceTokens && options.AccessTokenFormat == null)
            {
                var protector = options.DataProtectionProvider.CreateProtector(
                    "OpenIdConnectServerHandler",
                    nameof(options.AccessTokenFormat),
                    nameof(options.UseReferenceTokens), "ASOS");

                options.AccessTokenFormat = new TicketDataFormat(protector);
            }
        }
    }
}
