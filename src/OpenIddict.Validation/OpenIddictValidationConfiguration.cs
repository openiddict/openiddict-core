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
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using static OpenIddict.Validation.OpenIddictValidationEvents;

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
                throw new InvalidOperationException("The security token handler cannot be null.");
            }

            if (options.Configuration == null && options.ConfigurationManager == null &&
                options.Issuer == null && options.MetadataAddress == null)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("An OAuth 2.0/OpenID Connect server configuration or an issuer address must be registered.")
                    .Append("To use a local OpenIddict server, reference the 'OpenIddict.Validation.ServerIntegration' package ")
                    .AppendLine("and call 'services.AddOpenIddict().AddValidation().UseLocalServer()' to import the server settings.")
                    .Append("To use a remote server, reference the 'OpenIddict.Validation.SystemNetHttp' package and call ")
                    .Append("'services.AddOpenIddict().AddValidation().UseSystemNetHttp()' ")
                    .AppendLine("and 'services.AddOpenIddict().AddValidation().SetIssuer()' to use server discovery.")
                    .Append("Alternatively, you can register a static server configuration by calling ")
                    .Append("'services.AddOpenIddict().AddValidation().SetConfiguration()'.")
                    .ToString());
            }

            if (options.ValidationType == OpenIddictValidationType.Introspection)
            {
                if (!options.DefaultHandlers.Any(descriptor => descriptor.ContextType == typeof(ApplyIntrospectionRequestContext)))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("An introspection client must be registered when using introspection.")
                        .Append("Reference the 'OpenIddict.Validation.SystemNetHttp' package and call ")
                        .Append("'services.AddOpenIddict().AddValidation().UseSystemNetHttp()' ")
                        .Append("to register the default System.Net.Http-based integration.")
                        .ToString());
                }

                if (options.Issuer == null && options.MetadataAddress == null)
                {
                    throw new InvalidOperationException("The issuer or the metadata address must be set when using introspection.");
                }

                if (string.IsNullOrEmpty(options.ClientId))
                {
                    throw new InvalidOperationException("The client identifier cannot be null or empty when using introspection.");
                }

                if (string.IsNullOrEmpty(options.ClientSecret))
                {
                    throw new InvalidOperationException("The client secret cannot be null or empty when using introspection.");
                }

                if (options.EnableAuthorizationEntryValidation)
                {
                    throw new InvalidOperationException("Authorization validation cannot be enabled when using introspection.");
                }

                if (options.EnableTokenEntryValidation)
                {
                    throw new InvalidOperationException("Token validation cannot be enabled when using introspection.");
                }
            }

            if (options.Configuration == null && options.ConfigurationManager == null)
            {
                if (!options.DefaultHandlers.Any(descriptor => descriptor.ContextType == typeof(ApplyConfigurationRequestContext)) ||
                    !options.DefaultHandlers.Any(descriptor => descriptor.ContextType == typeof(ApplyCryptographyRequestContext)))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("A discovery client must be registered when using server discovery.")
                        .Append("Reference the 'OpenIddict.Validation.SystemNetHttp' package and call ")
                        .Append("'services.AddOpenIddict().AddValidation().UseSystemNetHttp()' ")
                        .Append("to register the default System.Net.Http-based integration.")
                        .ToString());
                }

                if (options.MetadataAddress == null)
                {
                    options.MetadataAddress = new Uri(".well-known/openid-configuration", UriKind.Relative);
                }

                if (!options.MetadataAddress.IsAbsoluteUri)
                {
                    if (options.Issuer == null || !options.Issuer.IsAbsoluteUri)
                    {
                        throw new InvalidOperationException("The authority must be provided and must be an absolute URL.");
                    }

                    if (!string.IsNullOrEmpty(options.Issuer.Fragment) || !string.IsNullOrEmpty(options.Issuer.Query))
                    {
                        throw new InvalidOperationException("The authority cannot contain a fragment or a query string.");
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
        }
    }
}
