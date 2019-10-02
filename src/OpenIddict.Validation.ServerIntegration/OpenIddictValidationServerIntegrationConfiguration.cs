/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using JetBrains.Annotations;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace OpenIddict.Validation.ServerIntegration
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict validation/server integration configuration is valid.
    /// </summary>
    public class OpenIddictValidationServerIntegrationConfiguration : IConfigureOptions<OpenIddictValidationOptions>
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

            // Import the symmetric encryption keys from the server configuration.
            foreach (var credentials in _options.CurrentValue.EncryptionCredentials)
            {
                if (credentials.Key is SymmetricSecurityKey)
                {
                    options.EncryptionCredentials.Add(credentials);
                }
            }

            options.UseReferenceTokens = _options.CurrentValue.UseReferenceTokens;
        }
    }
}
