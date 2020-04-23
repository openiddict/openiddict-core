/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Text;
using JetBrains.Annotations;
using Microsoft.Extensions.Options;
using OpenIddict.Server;

namespace OpenIddict.Validation.ServerIntegration
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict validation/server integration configuration is valid.
    /// </summary>
    public class OpenIddictValidationServerIntegrationConfiguration : IConfigureOptions<OpenIddictValidationOptions>,
                                                                      IPostConfigureOptions<OpenIddictValidationOptions>
    {
        private readonly IOptionsMonitor<OpenIddictServerOptions> _options;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictValidationServerIntegrationConfiguration"/> class.
        /// </summary>
        /// <param name="options">The OpenIddict server options.</param>
        public OpenIddictValidationServerIntegrationConfiguration([NotNull] IOptionsMonitor<OpenIddictServerOptions> options)
            => _options = options;

        /// <summary>
        /// Populates the default OpenIddict validation/server integration options
        /// and ensures that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="options">The options instance to initialize.</param>
        public void Configure([NotNull] OpenIddictValidationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // Note: the issuer may be null. In this case, it will be usually be provided by
            // a validation handler registered by the host (e.g ASP.NET Core or OWIN/Katana)
            options.Issuer = _options.CurrentValue.Issuer;

            // Import the token validation parameters from the server configuration.
            options.TokenValidationParameters.IssuerSigningKeys =
                (from credentials in _options.CurrentValue.SigningCredentials
                 select credentials.Key).ToList();

            // Import the encryption keys from the server configuration.
            foreach (var credentials in _options.CurrentValue.EncryptionCredentials)
            {
                options.EncryptionCredentials.Add(credentials);
            }

            // Note: token validation must be enabled to be able to validate reference tokens.
            options.EnableTokenValidation = _options.CurrentValue.UseReferenceTokens;
        }

        /// <summary>
        /// Populates the default OpenIddict validation/server integration options
        /// and ensures that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The name of the options instance to configure, if applicable.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([CanBeNull] string name, [NotNull] OpenIddictValidationOptions options)
        {
            // Note: authorization validation requires that authorizations have an entry
            // in the database (containing at least the authorization metadata), which is
            // not created if the authorization storage is disabled in the server options.
            if (options.EnableAuthorizationValidation && _options.CurrentValue.DisableAuthorizationStorage)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .Append("Authorization validation cannot be enabled when authorization ")
                    .Append("storage is disabled in the OpenIddict server options.")
                    .ToString());
            }

            // Note: token validation requires that tokens have an entry in the database
            // (containing at least the token metadata), which is not created if the
            // token storage is disabled in the OpenIddict server options.
            if (options.EnableTokenValidation && _options.CurrentValue.DisableTokenStorage)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .Append("Token validation cannot be enabled when token storage ")
                    .Append("is disabled in the OpenIddict server options.")
                    .ToString());
            }
        }
    }
}
