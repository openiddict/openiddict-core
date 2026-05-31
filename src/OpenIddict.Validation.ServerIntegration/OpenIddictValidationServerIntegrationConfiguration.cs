/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Server;

namespace OpenIddict.Validation.ServerIntegration;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict validation/server integration configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictValidationServerIntegrationConfiguration : IConfigureOptions<OpenIddictValidationOptions>,
                                                                         IValidateOptions<OpenIddictValidationOptions>
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictValidationServerIntegrationConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictValidationServerIntegrationConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void Configure(OpenIddictValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var settings = _provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

        // Note: the issuer may be null. In this case, it will be usually provided by
        // a validation handler registered by the host (e.g ASP.NET Core or OWIN/Katana).
        options.Issuer = settings.Issuer;
        options.Configuration = new OpenIddictConfiguration
        {
            Issuer = options.Issuer
        };

        // Import the signing keys from the server configuration.
        foreach (var credentials in settings.SigningCredentials)
        {
            options.Configuration.SigningKeys.Add(credentials.Key);
        }

        // Import the encryption keys from the server configuration.
        options.EncryptionCredentials.AddRange(settings.EncryptionCredentials);

        // Note: token entry validation must be enabled to be able to validate reference access tokens.
        options.EnableTokenEntryValidation = settings.UseReferenceAccessTokens;
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, OpenIddictValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var builder = new ValidateOptionsResultBuilder();

        var settings = _provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

        if (options.ValidationType is not OpenIddictValidationType.Direct)
        {
            builder.AddError(SR.GetResourceString(SR.ID0170));
        }

        // Note: authorization validation requires that authorizations have an entry
        // in the database (containing at least the authorization metadata), which is
        // not created if the authorization storage is disabled in the server options.
        if (options.EnableAuthorizationEntryValidation && settings.DisableAuthorizationStorage)
        {
            builder.AddError(SR.GetResourceString(SR.ID0171));
        }

        // Note: token validation requires that tokens have an entry in the database
        // (containing at least the token metadata), which is not created if the
        // token storage is disabled in the OpenIddict server options.
        if (options.EnableTokenEntryValidation && settings.DisableTokenStorage)
        {
            builder.AddError(SR.GetResourceString(SR.ID0172));
        }

        return builder.Build();
    }
}
