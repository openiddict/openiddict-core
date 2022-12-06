/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;

namespace OpenIddict.Validation;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict validation configuration is valid.
/// </summary>
public sealed class OpenIddictValidationConfiguration : IPostConfigureOptions<OpenIddictValidationOptions>
{
    private readonly OpenIddictValidationService _service;

    public OpenIddictValidationConfiguration(OpenIddictValidationService service)
        => _service = service ?? throw new ArgumentNullException(nameof(service));

    /// <summary>
    /// Populates the default OpenIddict validation options and ensures
    /// that the configuration is in a consistent and valid state.
    /// </summary>
    /// <param name="name">The name of the options instance to configure, if applicable.</param>
    /// <param name="options">The options instance to initialize.</param>
    public void PostConfigure(string? name, OpenIddictValidationOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (options.JsonWebTokenHandler is null)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0075));
        }

        if (options.Configuration is null && options.ConfigurationManager is null &&
            options.Issuer is null && options.ConfigurationEndpoint is null)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0128));
        }

        if (options.Issuer is not null && (!string.IsNullOrEmpty(options.Issuer.Fragment) ||
                                           !string.IsNullOrEmpty(options.Issuer.Query)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0137));
        }

        if (options.ValidationType is OpenIddictValidationType.Introspection)
        {
            if (!options.Handlers.Exists(static descriptor => descriptor.ContextType == typeof(ApplyIntrospectionRequestContext)))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0129));
            }

            if (options.Issuer is null && options.ConfigurationEndpoint is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0130));
            }

            if (string.IsNullOrEmpty(options.ClientId))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0131));
            }

            if (string.IsNullOrEmpty(options.ClientSecret))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0132));
            }

            if (options.EnableAuthorizationEntryValidation)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0133));
            }

            if (options.EnableTokenEntryValidation)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0134));
            }
        }

        // If all the registered encryption credentials are backed by a X.509 certificate, at least one of them must be valid.
        if (options.EncryptionCredentials.Count is not 0 &&
            options.EncryptionCredentials.TrueForAll(credentials => credentials.Key is X509SecurityKey x509SecurityKey &&
                (x509SecurityKey.Certificate.NotBefore > DateTime.Now || x509SecurityKey.Certificate.NotAfter < DateTime.Now)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0087));
        }

        if (options.ConfigurationManager is null)
        {
            if (options.Configuration is not null)
            {
                options.Configuration.Issuer = options.Issuer;
                options.ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(options.Configuration);
            }

            else
            {
                if (!options.Handlers.Exists(static descriptor => descriptor.ContextType == typeof(ApplyConfigurationRequestContext)) ||
                    !options.Handlers.Exists(static descriptor => descriptor.ContextType == typeof(ApplyCryptographyRequestContext)))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0135));
                }

                options.ConfigurationEndpoint = OpenIddictHelpers.CreateAbsoluteUri(
                    options.Issuer,
                    options.ConfigurationEndpoint ?? new Uri(".well-known/openid-configuration", UriKind.Relative));

                options.ConfigurationManager = new ConfigurationManager<OpenIddictConfiguration>(
                    options.ConfigurationEndpoint.AbsoluteUri, new OpenIddictValidationRetriever(_service))
                {
                    AutomaticRefreshInterval = ConfigurationManager<OpenIddictConfiguration>.DefaultAutomaticRefreshInterval,
                    RefreshInterval = ConfigurationManager<OpenIddictConfiguration>.DefaultRefreshInterval
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
