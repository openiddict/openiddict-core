/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using JetBrains.Annotations;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using SR = OpenIddict.Abstractions.Resources.OpenIddictResources;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict validation configuration is valid.
    /// </summary>
    public class OpenIddictValidationConfiguration : IPostConfigureOptions<OpenIddictValidationOptions>
    {
        private readonly OpenIddictValidationService _service;

        public OpenIddictValidationConfiguration([NotNull] OpenIddictValidationService service)
            => _service = service;

        /// <summary>
        /// Populates the default OpenIddict validation options and ensures
        /// that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The name of the options instance to configure, if applicable.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([CanBeNull] string name, [NotNull] OpenIddictValidationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (options.JsonWebTokenHandler == null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1074));
            }

            if (options.Configuration == null && options.ConfigurationManager == null &&
                options.Issuer == null && options.MetadataAddress == null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1127));
            }

            if (options.ValidationType == OpenIddictValidationType.Introspection)
            {
                if (!options.Handlers.Any(descriptor => descriptor.ContextType == typeof(ApplyIntrospectionRequestContext)))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1128));
                }

                if (options.Issuer == null && options.MetadataAddress == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1129));
                }

                if (string.IsNullOrEmpty(options.ClientId))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1130));
                }

                if (string.IsNullOrEmpty(options.ClientSecret))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1131));
                }

                if (options.EnableAuthorizationEntryValidation)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1132));
                }

                if (options.EnableTokenEntryValidation)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1133));
                }
            }

            // If all the registered encryption credentials are backed by a X.509 certificate, at least one of them must be valid.
            if (options.EncryptionCredentials.Count != 0 &&
                options.EncryptionCredentials.All(credentials => credentials.Key is X509SecurityKey x509SecurityKey &&
                    (x509SecurityKey.Certificate.NotBefore > DateTime.Now || x509SecurityKey.Certificate.NotAfter < DateTime.Now)))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1086));
            }

            if (options.Configuration == null && options.ConfigurationManager == null)
            {
                if (!options.Handlers.Any(descriptor => descriptor.ContextType == typeof(ApplyConfigurationRequestContext)) ||
                    !options.Handlers.Any(descriptor => descriptor.ContextType == typeof(ApplyCryptographyRequestContext)))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1134));
                }

                if (options.MetadataAddress == null)
                {
                    options.MetadataAddress = new Uri(".well-known/openid-configuration", UriKind.Relative);
                }

                if (!options.MetadataAddress.IsAbsoluteUri)
                {
                    if (options.Issuer == null || !options.Issuer.IsAbsoluteUri)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1135));
                    }

                    if (!string.IsNullOrEmpty(options.Issuer.Fragment) || !string.IsNullOrEmpty(options.Issuer.Query))
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1136));
                    }

                    if (!options.Issuer.OriginalString.EndsWith("/"))
                    {
                        options.Issuer = new Uri(options.Issuer.OriginalString + "/", UriKind.Absolute);
                    }

                    if (options.MetadataAddress.OriginalString.StartsWith("/"))
                    {
                        options.MetadataAddress = new Uri(options.MetadataAddress.OriginalString.Substring(
                            1, options.MetadataAddress.OriginalString.Length - 1), UriKind.Relative);
                    }

                    options.MetadataAddress = new Uri(options.Issuer, options.MetadataAddress);
                }
            }

            if (options.ConfigurationManager == null)
            {
                if (options.Configuration != null)
                {
                    options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(options.Configuration);
                }

                else
                {
                    options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                        options.MetadataAddress.AbsoluteUri, new OpenIddictValidationRetriever(_service))
                    {
                        AutomaticRefreshInterval = ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval,
                        RefreshInterval = ConfigurationManager<OpenIdConnectConfiguration>.DefaultRefreshInterval
                    };
                }
            }

            // Sort the handlers collection using the order associated with each handler.
            options.Handlers.Sort((left, right) => left.Order.CompareTo(right.Order));

            // Attach the encryption credentials to the token validation parameters.
            options.TokenValidationParameters.TokenDecryptionKeys =
                from credentials in options.EncryptionCredentials
                select credentials.Key;
        }
    }
}
