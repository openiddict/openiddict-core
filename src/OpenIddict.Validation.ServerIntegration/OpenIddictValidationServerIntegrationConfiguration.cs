/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OpenIddict.Server;

namespace OpenIddict.Validation.ServerIntegration;

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
    public OpenIddictValidationServerIntegrationConfiguration(IOptionsMonitor<OpenIddictServerOptions> options)
        => _options = options;

    /// <summary>
    /// Populates the default OpenIddict validation/server integration options
    /// and ensures that the configuration is in a consistent and valid state.
    /// </summary>
    /// <param name="options">The options instance to initialize.</param>
    public void Configure(OpenIddictValidationOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Note: the issuer may be null. In this case, it will be usually provided by
        // a validation handler registered by the host (e.g ASP.NET Core or OWIN/Katana).
        options.Configuration = new OpenIdConnectConfiguration
        {
            Issuer = _options.CurrentValue.Issuer?.AbsoluteUri
        };

        // Import the signing keys from the server configuration.
        foreach (var credentials in _options.CurrentValue.SigningCredentials)
        {
            options.Configuration.SigningKeys.Add(credentials.Key);
        }

        // Import the encryption keys from the server configuration.
        options.EncryptionCredentials.AddRange(_options.CurrentValue.EncryptionCredentials);

        // Note: token entry validation must be enabled to be able to validate reference access tokens.
        options.EnableTokenEntryValidation = _options.CurrentValue.UseReferenceAccessTokens;
    }

    /// <summary>
    /// Populates the default OpenIddict validation/server integration options
    /// and ensures that the configuration is in a consistent and valid state.
    /// </summary>
    /// <param name="name">The name of the options instance to configure, if applicable.</param>
    /// <param name="options">The options instance to initialize.</param>
    public void PostConfigure(string name, OpenIddictValidationOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (options.ValidationType != OpenIddictValidationType.Direct)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0170));
        }

        // Note: authorization validation requires that authorizations have an entry
        // in the database (containing at least the authorization metadata), which is
        // not created if the authorization storage is disabled in the server options.
        if (options.EnableAuthorizationEntryValidation && _options.CurrentValue.DisableAuthorizationStorage)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0171));
        }

        // Note: token validation requires that tokens have an entry in the database
        // (containing at least the token metadata), which is not created if the
        // token storage is disabled in the OpenIddict server options.
        if (options.EnableTokenEntryValidation && _options.CurrentValue.DisableTokenStorage)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0172));
        }
    }
}
