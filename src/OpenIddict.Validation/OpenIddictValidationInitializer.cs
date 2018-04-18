using System;
using System.ComponentModel;
using AspNet.Security.OAuth.Validation;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Contains the methods required to ensure that the configuration used by
    /// the OAuth2 validation handler is in a consistent and valid state.
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
        /// Populates the default OAuth2 validation options and ensure
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

            if (options.Events == null)
            {
                options.Events = new OAuthValidationEvents();
            }

            if (options.DataProtectionProvider == null)
            {
                options.DataProtectionProvider = _dataProtectionProvider;
            }

            if (options.AccessTokenFormat == null)
            {
                if (options.UseReferenceTokens)
                {
                    var protector = options.DataProtectionProvider.CreateProtector(
                        "OpenIdConnectServerHandler",
                        nameof(options.AccessTokenFormat),
                        nameof(options.UseReferenceTokens), "ASOS");

                    options.AccessTokenFormat = new TicketDataFormat(protector);
                }
                else
                {
                    var protector = options.DataProtectionProvider.CreateProtector(
                        "OpenIdConnectServerHandler",
                        nameof(options.AccessTokenFormat), "ASOS");

                    options.AccessTokenFormat = new TicketDataFormat(protector);
                }
            }

        }
    }
}
