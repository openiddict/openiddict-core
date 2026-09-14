/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using OpenIddict.Server;

namespace OpenIddict.Validation.ServerIntegration;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict validation/server integration configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictValidationServerIntegrationConfiguration : IConfigureOptions<OpenIddictValidationOptions>,
                                                                         IValidateOptions<OpenIddictValidationOptions>,
                                                                         IOptionsChangeTokenSource<OpenIddictValidationOptions>
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

        // When issuer resolution is enabled, the issuer is resolved per request using the same logic as the server
        // and tokens are validated against the resolved issuer and its credentials. Requests for which no issuer
        // can be resolved are rejected, as the issuer can't be safely inferred from the request host in this case.
        if (settings.EnableIssuerResolution)
        {
            options.Handlers.Add(OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseInlineHandler(static async context =>
                {
                    var server = context.Transaction.ServiceProvider
                        .GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

                    var issuer = context is { BaseUri.IsAbsoluteUri: true, RequestUri.IsAbsoluteUri: true } ?
                        await OpenIddictServerIssuerResolution.ResolveIssuerAsync(new()
                        {
                            BaseUri = context.BaseUri,
                            CancellationToken = context.CancellationToken,
                            Options = server,
                            Properties = context.Transaction.Properties,
                            RequestUri = context.RequestUri,
                            ServiceProvider = context.Transaction.ServiceProvider
                        }) : null;

                    if (issuer is null)
                    {
                        context.BaseUri = null;

                        context.Reject(
                            error: Errors.InvalidToken,
                            description: SR.GetResourceString(SR.ID2465),
                            uri: SR.FormatID8000(SR.ID2465));

                        return;
                    }

                    context.BaseUri = issuer;
                })
                .SetOrder(OpenIddictValidationHandlers.EvaluateValidatedTokens.Descriptor.Order - 25_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build());

            options.Handlers.Add(OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                .UseInlineHandler(static async context =>
                {
                    var server = context.Transaction.ServiceProvider
                        .GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

                    if (context.BaseUri is not { IsAbsoluteUri: true } issuer)
                    {
                        return;
                    }

                    // Note: only the credentials of the resolved issuer are used to unprotect tokens.
                    var credentials = await OpenIddictServerKeyRing.ResolveCredentialsAsync(
                        context.Transaction.ServiceProvider, server, issuer, context.CancellationToken);

                    var parameters = context.TokenValidationParameters;
                    parameters.IssuerSigningKeys = [.. from signing in credentials.SigningCredentials select signing.Key];
                    parameters.TokenDecryptionKeys = [.. from encryption in credentials.EncryptionCredentials select encryption.Key];
                })
                .SetOrder(OpenIddictValidationHandlers.Protection.ResolveTokenValidationParameters.Descriptor.Order + 500)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build());

            options.Handlers.Add(OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                .UseInlineHandler(static context =>
                {
                    // Note: JSON Web Tokens are already validated by IdentityModel but tokens
                    // using a different format (e.g Data Protection tokens) are not.
                    if (context.Principal is not null && (context.BaseUri is not { IsAbsoluteUri: true } issuer ||
                        !OpenIddictServerIssuerResolution.IsIssuedBy(context.Principal, issuer)))
                    {
                        context.Reject(
                            error: Errors.InvalidToken,
                            description: SR.GetResourceString(SR.ID2464),
                            uri: SR.FormatID8000(SR.ID2464));
                    }

                    return ValueTask.CompletedTask;
                })
                .SetOrder(OpenIddictValidationHandlers.Protection.ValidatePrincipal.Descriptor.Order + 500)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build());
        }

        // When automatic key management is enabled, the keys change over time and are
        // resolved from the server key ring every time a token is validated.
        else if (settings.EnableAutomaticKeyManagement)
        {
            options.Handlers.Add(OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                .UseInlineHandler(static async context =>
                {
                    var credentials = await context.Transaction.ServiceProvider
                        .GetRequiredService<OpenIddictServerKeyRing>()
                        .GetCredentialsAsync(context.Transaction.ServiceProvider, context.CancellationToken);

                    var parameters = context.TokenValidationParameters;

                    parameters.IssuerSigningKeys = [
                        .. parameters.IssuerSigningKeys ?? [],
                        .. from signing in credentials.SigningCredentials select signing.Key];

                    parameters.TokenDecryptionKeys = [
                        .. parameters.TokenDecryptionKeys ?? [],
                        .. from encryption in credentials.EncryptionCredentials select encryption.Key];
                })
                .SetOrder(OpenIddictValidationHandlers.Protection.ResolveTokenValidationParameters.Descriptor.Order + 500)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build());
        }

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

    /// <inheritdoc/>
    IChangeToken IOptionsChangeTokenSource<OpenIddictValidationOptions>.GetChangeToken() => new CompositeChangeToken(
    [
        // Force the options to be re-evaluated when the related instances from which they are populated are changed.
        .. from source in _provider.GetServices<IOptionsChangeTokenSource<OpenIddictServerOptions>>()
           select source.GetChangeToken()
    ]);

    /// <inheritdoc/>
    string? IOptionsChangeTokenSource<OpenIddictValidationOptions>.Name => Options.DefaultName;
}
