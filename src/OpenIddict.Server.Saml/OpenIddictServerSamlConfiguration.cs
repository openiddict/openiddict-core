/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict SAML configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerSamlConfiguration : IPostConfigureOptions<OpenIddictServerSamlOptions>,
                                                        IValidateOptions<OpenIddictServerSamlOptions>
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSamlConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictServerSamlConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictServerSamlOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.TimeProvider ??= _provider.GetService<TimeProvider>() ?? TimeProvider.System;

        // Note: the server options are only resolved when they are needed, as resolving
        // them triggers the validation of the entire server configuration.
        if (string.IsNullOrEmpty(options.EntityId) || options.SigningCertificates.Count is 0)
        {
            var server = _provider.GetService<IOptionsMonitor<OpenIddictServerOptions>>()?.CurrentValue;
            if (server is null)
            {
                return;
            }

            if (string.IsNullOrEmpty(options.EntityId) && server.Issuer is { IsAbsoluteUri: true } issuer)
            {
                options.EntityId = issuer.AbsoluteUri;
            }

            if (options.SigningCertificates.Count is 0)
            {
                foreach (var credentials in server.SigningCredentials)
                {
                    if (credentials.Key is X509SecurityKey { Certificate: { HasPrivateKey: true } certificate } &&
                        IsRsaCertificate(certificate))
                    {
                        options.SigningCertificates.Add(certificate);
                    }
                }
            }
        }
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, OpenIddictServerSamlOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrEmpty(options.EntityId))
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0565));
        }

        if (options.SigningCertificates.Count is 0 ||
            options.SigningCertificates.Exists(static certificate => !IsRsaCertificate(certificate)) ||
           !options.SigningCertificates.Exists(static certificate => certificate.HasPrivateKey))
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0566));
        }

        if (options.AssertionLifetime <= TimeSpan.Zero || options.AuthenticationRequestLifetime <= TimeSpan.Zero ||
            options.ClockSkew < TimeSpan.Zero || options.MaximumMessageSize <= 0)
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0572));
        }

        if (options.ArtifactLifetime <= TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0845));
        }

        if (!OpenIddictServerSamlHelpers.IsSupportedDataEncryptionAlgorithm(options.DataEncryptionAlgorithm) ||
            !OpenIddictServerSamlHelpers.IsSupportedKeyTransportAlgorithm(options.KeyTransportAlgorithm))
        {
            return ValidateOptionsResult.Fail(SR.FormatID0842(options.DataEncryptionAlgorithm, options.KeyTransportAlgorithm));
        }

        if (OpenIddict.Extensions.OpenIddictSamlHelpers.GetHashAlgorithm(options.SignatureAlgorithm) is null ||
            !OpenIddict.Extensions.OpenIddictSamlHelpers.IsSupportedDigestAlgorithm(options.DigestAlgorithm))
        {
            return ValidateOptionsResult.Fail(SR.FormatID0573(options.SignatureAlgorithm, options.DigestAlgorithm));
        }

        var identifiers = new HashSet<string>(StringComparer.Ordinal);

        foreach (var provider in options.ServiceProviders)
        {
            try
            {
                ValidateServiceProvider(provider, options);
            }

            catch (InvalidOperationException exception)
            {
                return ValidateOptionsResult.Fail(exception.Message);
            }

            if (!identifiers.Add(provider.EntityId!))
            {
                return ValidateOptionsResult.Fail(SR.FormatID0570(provider.EntityId));
            }
        }

        return ValidateOptionsResult.Success;
    }

    private static bool IsRsaCertificate(X509Certificate2 certificate)
        => OpenIddict.Extensions.OpenIddictSamlHelpers.IsRsaCertificate(certificate);

    /// <summary>
    /// Ensures the specified service provider is valid.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    /// <exception cref="InvalidOperationException">The service provider is invalid.</exception>
    public static void ValidateServiceProvider(OpenIddictServerSamlServiceProvider provider)
        => ValidateServiceProvider(provider, options: null);

    /// <summary>
    /// Ensures the specified service provider is valid and compatible with the identity provider options.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    /// <param name="options">The SAML options, if available.</param>
    /// <exception cref="InvalidOperationException">The service provider is invalid.</exception>
    public static void ValidateServiceProvider(OpenIddictServerSamlServiceProvider provider, OpenIddictServerSamlOptions? options)
    {
        ArgumentNullException.ThrowIfNull(provider);

        ValidateCoreSettings(provider);

        foreach (var binding in provider.AssertionConsumerServiceBindings)
        {
            if (binding.Key < 0 || binding.Key >= provider.AssertionConsumerServiceUrls.Count ||
                binding.Value is not (OpenIddictServerSamlConstants.Bindings.HttpPost or OpenIddictServerSamlConstants.Bindings.HttpArtifact))
            {
                throw new InvalidOperationException(SR.FormatID0840(provider.EntityId));
            }

            // Note: the requester of an artifact resolution must be authenticated (SAML bindings, 3.6.5.2),
            // which is only supported using a signed ArtifactResolve message (TLS client authentication isn't).
            if (binding.Value is OpenIddictServerSamlConstants.Bindings.HttpArtifact &&
                ((options is not null && !options.EnableArtifactBinding) || provider.SigningCertificates.Count is 0))
            {
                throw new InvalidOperationException(SR.FormatID0843(provider.EntityId));
            }
        }

        if (provider.EncryptAssertions && (provider.EncryptionCertificate is null || !IsRsaCertificate(provider.EncryptionCertificate)))
        {
            throw new InvalidOperationException(SR.FormatID0844(provider.EntityId));
        }

        if ((provider.DataEncryptionAlgorithm is not null &&
            !OpenIddictServerSamlHelpers.IsSupportedDataEncryptionAlgorithm(provider.DataEncryptionAlgorithm)) ||
            (provider.KeyTransportAlgorithm is not null &&
            !OpenIddictServerSamlHelpers.IsSupportedKeyTransportAlgorithm(provider.KeyTransportAlgorithm)))
        {
            throw new InvalidOperationException(SR.FormatID0842(provider.DataEncryptionAlgorithm, provider.KeyTransportAlgorithm));
        }
    }

    private static void ValidateCoreSettings(OpenIddictServerSamlServiceProvider provider)
    {
        if (string.IsNullOrEmpty(provider.EntityId))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0567));
        }

        if (provider.AssertionConsumerServiceUrls.Count is 0 || provider.AssertionConsumerServiceUrls.Exists(static url =>
            url is null || !url.IsAbsoluteUri || !string.IsNullOrEmpty(url.Fragment) ||
            (!string.Equals(url.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
             !string.Equals(url.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))))
        {
            throw new InvalidOperationException(SR.FormatID0568(provider.EntityId));
        }

        if (provider.RequireSignedAuthenticationRequests && provider.SigningCertificates.Count is 0)
        {
            throw new InvalidOperationException(SR.FormatID0569(provider.EntityId));
        }

        if (provider.AssertionLifetime is TimeSpan lifetime && lifetime <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(SR.FormatID0577(provider.EntityId));
        }
    }
}
