/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Client.Saml.OpenIddictClientSamlConstants;
using SamlHelpers = OpenIddict.Extensions.OpenIddictSamlHelpers;

namespace OpenIddict.Client.Saml;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict SAML service provider configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientSamlConfiguration : IPostConfigureOptions<OpenIddictClientSamlOptions>,
                                                        IValidateOptions<OpenIddictClientSamlOptions>
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSamlConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictClientSamlConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictClientSamlOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.TimeProvider ??= _provider.GetService<TimeProvider>() ?? TimeProvider.System;

        foreach (var registration in options.Registrations)
        {
            ConfigureRegistration(registration);
        }
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, OpenIddictClientSamlOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrEmpty(options.EntityId))
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0880));
        }

        if (options.SigningCertificates.Exists(static certificate => !IsRsaCertificateWithPrivateKey(certificate)))
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0881));
        }

        if (options.EncryptionCertificates.Exists(static certificate => !IsRsaCertificateWithPrivateKey(certificate)))
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0882));
        }

        if (options.ClockSkew < TimeSpan.Zero || options.RequestStateLifetime <= TimeSpan.Zero ||
            options.MetadataRefreshInterval <= TimeSpan.Zero || options.MaximumMessageSize <= 0 || options.MaximumMetadataSize <= 0)
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0883));
        }

        if (SamlHelpers.GetHashAlgorithm(options.SignatureAlgorithm) is null ||
           !SamlHelpers.IsSupportedDigestAlgorithm(options.DigestAlgorithm))
        {
            return ValidateOptionsResult.Fail(SR.FormatID0884(options.SignatureAlgorithm, options.DigestAlgorithm));
        }

        var identifiers = new HashSet<string>(StringComparer.Ordinal);

        foreach (var registration in options.Registrations)
        {
            try
            {
                ValidateRegistration(options, registration);
            }

            catch (InvalidOperationException exception)
            {
                return ValidateOptionsResult.Fail(exception.Message);
            }

            if (!identifiers.Add(registration.RegistrationId!))
            {
                return ValidateOptionsResult.Fail(SR.FormatID0891(registration.RegistrationId));
            }
        }

        return ValidateOptionsResult.Success;
    }

    /// <summary>
    /// Initializes the specified registration (e.g computes its default identifier).
    /// </summary>
    /// <param name="registration">The registration.</param>
    public static void ConfigureRegistration(OpenIddictClientSamlRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);

        if (string.IsNullOrEmpty(registration.RegistrationId) &&
           (!string.IsNullOrEmpty(registration.IdentityProviderEntityId) || registration.MetadataAddress is { IsAbsoluteUri: true }))
        {
            registration.RegistrationId = ComputeDefaultRegistrationId(registration);
        }
    }

    /// <summary>
    /// Ensures the specified registration is valid.
    /// </summary>
    /// <param name="options">The SAML options.</param>
    /// <param name="registration">The registration.</param>
    /// <exception cref="InvalidOperationException">The registration is invalid.</exception>
    public static void ValidateRegistration(OpenIddictClientSamlOptions options, OpenIddictClientSamlRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(registration);

        if (string.IsNullOrEmpty(registration.RegistrationId) ||
           (string.IsNullOrEmpty(registration.IdentityProviderEntityId) && registration.MetadataAddress is null))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0885));
        }

        if (registration.MetadataAddress is Uri address && (!address.IsAbsoluteUri ||
            (!address.IsFile && !string.Equals(address.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))))
        {
            throw new InvalidOperationException(SR.FormatID0888(registration.RegistrationId));
        }

        if (registration.MetadataAddress is null &&
           (registration.SingleSignOnServiceUrl is null || registration.SigningCertificates.Count is 0))
        {
            throw new InvalidOperationException(SR.FormatID0886(registration.RegistrationId));
        }

        if (registration.SingleSignOnServiceUrl is Uri url && (!url.IsAbsoluteUri || !string.IsNullOrEmpty(url.Fragment) ||
            (!string.Equals(url.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
             !string.Equals(url.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))))
        {
            throw new InvalidOperationException(SR.FormatID0887(registration.RegistrationId));
        }

        if (registration.AuthenticationRequestBinding is not (Bindings.HttpRedirect or Bindings.HttpPost))
        {
            throw new InvalidOperationException(SR.FormatID0889(registration.RegistrationId));
        }

        if (registration.SigningCertificates.Exists(static certificate => certificate is null || !SamlHelpers.IsRsaCertificate(certificate)) ||
            registration.MetadataSigningCertificates.Exists(static certificate => certificate is null || !SamlHelpers.IsRsaCertificate(certificate)))
        {
            throw new InvalidOperationException(SR.FormatID0890(registration.RegistrationId));
        }

        if (registration.AllowUnsolicitedResponses && string.IsNullOrEmpty(registration.IdentityProviderEntityId))
        {
            throw new InvalidOperationException(SR.FormatID0892(registration.RegistrationId));
        }

        if (registration.SignAuthenticationRequests is true && options.SigningCertificates.Count is 0)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0881));
        }
    }

    /// <summary>
    /// Computes the default identifier of a registration from its identity provider entity identifier
    /// (or metadata address) and its provider name.
    /// </summary>
    internal static string ComputeDefaultRegistrationId(OpenIddictClientSamlRegistration registration)
    {
        var builder = new StringBuilder()
            .Append(registration.IdentityProviderEntityId ?? registration.MetadataAddress?.AbsoluteUri)
            .Append('\n')
            .Append(registration.ProviderName);

#if NET
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
#else
        using var algorithm = SHA256.Create();
        return Base64UrlEncoder.Encode(algorithm.ComputeHash(Encoding.UTF8.GetBytes(builder.ToString())));
#endif
    }

    private static bool IsRsaCertificateWithPrivateKey(X509Certificate2 certificate)
        => certificate is { HasPrivateKey: true } && SamlHelpers.IsRsaCertificate(certificate);
}
