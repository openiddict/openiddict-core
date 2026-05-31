/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict client configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientConfiguration : IPostConfigureOptions<OpenIddictClientOptions>,
                                                    IValidateOptions<OpenIddictClientOptions>
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictClientConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.TimeProvider ??= _provider.GetService<TimeProvider>() ?? TimeProvider.System;

        foreach (var registration in options.Registrations)
        {
            // If no explicit registration identifier was set, compute a stable
            // hash based on the issuer URI and the provider name, if available.
            if (registration.Issuer is not null && string.IsNullOrEmpty(registration.RegistrationId))
            {
                registration.RegistrationId = ComputeDefaultRegistrationId(registration);
            }

            // If no client type was explicitly set, assume the client is confidential if a client secret
            // or a signing key/certificate (typically used with private_key_jwt, tls_client_auth or
            // self_signed_tls_client_auth) has been attached to the client registration.
            if (string.IsNullOrEmpty(registration.ClientType))
            {
                registration.ClientType =
                    !string.IsNullOrEmpty(registration.ClientSecret) || registration.SigningCredentials.Count is > 0
                    ? ClientTypes.Confidential
                    : ClientTypes.Public;
            }

            if (registration.ConfigurationManager is null)
            {
                if (registration.Configuration is not null)
                {
                    registration.Configuration.Issuer ??= registration.Issuer;
                    registration.ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(registration.Configuration);
                }

                else if (registration.Issuer is not null)
                {
                    registration.ConfigurationEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                        registration.Issuer,
                        registration.ConfigurationEndpoint ?? new Uri(".well-known/openid-configuration", UriKind.Relative));

                    registration.ConfigurationManager = new ConfigurationManager<OpenIddictConfiguration>(
                        registration.ConfigurationEndpoint.AbsoluteUri,
                        new OpenIddictClientRetriever(_provider.GetRequiredService<OpenIddictClientService>(), registration))
                    {
                        AutomaticRefreshInterval = ConfigurationManager<OpenIddictConfiguration>.DefaultAutomaticRefreshInterval,
                        RefreshInterval = ConfigurationManager<OpenIddictConfiguration>.DefaultRefreshInterval
                    };
                }
            }
        }

        // Implicitly add the redirect_uri attached to the client registrations
        // to the list of redirection endpoints URIs if they haven't been added.
        options.RedirectionEndpointUris.AddRange(options.Registrations
            .Where(registration => registration.RedirectUri is not null)
            .Select(registration => registration.RedirectUri!)
            .Where(uri => !options.RedirectionEndpointUris.Contains(uri))
            .Distinct()
            .ToList());

        // Implicitly add the post_logout_redirect_uri attached to the client registrations
        // to the list of post-logout redirection endpoints URIs if they haven't been added.
        options.PostLogoutRedirectionEndpointUris.AddRange(options.Registrations
            .Where(registration => registration.PostLogoutRedirectUri is not null)
            .Select(registration => registration.PostLogoutRedirectUri!)
            .Where(uri => !options.PostLogoutRedirectionEndpointUris.Contains(uri))
            .Distinct()
            .ToList());

        // Sort the handlers collection using the order associated with each handler.
        options.Handlers.Sort((left, right) => left.Order.CompareTo(right.Order));

        var now = options.TimeProvider.GetUtcNow().LocalDateTime;

        // Sort the encryption and signing credentials.
        options.EncryptionCredentials.Sort((left, right) => Compare(left.Key, right.Key, now));
        options.SigningCredentials.Sort((left, right) => Compare(left.Key, right.Key, now));

        // Generate a key identifier for the encryption/signing keys that don't already have one.
        foreach (var key in options.EncryptionCredentials.Select(credentials => credentials.Key)
            .Concat(options.SigningCredentials.Select(credentials => credentials.Key))
            .Where(key => string.IsNullOrEmpty(key.KeyId)))
        {
            key.KeyId = GetKeyIdentifier(key);
        }

        // Attach the signing credentials to the token validation parameters.
        options.TokenValidationParameters.IssuerSigningKeys =
            from credentials in options.SigningCredentials
            select credentials.Key;

        // Attach the encryption credentials to the token validation parameters.
        options.TokenValidationParameters.TokenDecryptionKeys =
            from credentials in options.EncryptionCredentials
            select credentials.Key;

        static int Compare(SecurityKey left, SecurityKey right, DateTime now) => (left, right) switch
        {
            // If the two keys refer to the same instances, return 0.
            (SecurityKey first, SecurityKey second) when ReferenceEquals(first, second) => 0,

            // If one of the keys is a symmetric key, prefer it to the other one.
            (SymmetricSecurityKey, SymmetricSecurityKey) => 0,
            (SymmetricSecurityKey, SecurityKey) => -1,
            (SecurityKey, SymmetricSecurityKey) => 1,

            // If one of the keys is backed by a X.509 certificate, don't prefer it if it's not valid yet.
            (X509SecurityKey first, SecurityKey)  when first.Certificate.NotBefore  > now => 1,
            (SecurityKey, X509SecurityKey second) when second.Certificate.NotBefore > now => -1,

            // If the two keys are backed by a X.509 certificate, prefer the one with the furthest expiration date.
            (X509SecurityKey first, X509SecurityKey second) => -first.Certificate.NotAfter.CompareTo(second.Certificate.NotAfter),

            // If one of the keys is backed by a X.509 certificate, prefer the X.509 security key.
            (X509SecurityKey, SecurityKey) => -1,
            (SecurityKey, X509SecurityKey) => 1,

            // If the two keys are not backed by a X.509 certificate, none should be preferred to the other.
            (SecurityKey, SecurityKey) => 0
        };

        static string? GetKeyIdentifier(SecurityKey key)
        {
            // When no key identifier can be retrieved from the security keys, a value is automatically
            // inferred from the hexadecimal representation of the certificate thumbprint (SHA-1)
            // when the key is bound to a X.509 certificate or from the public part of the signing key.

            if (key is X509SecurityKey x509SecurityKey)
            {
                return x509SecurityKey.Certificate.Thumbprint;
            }

            if (key is RsaSecurityKey rsaSecurityKey)
            {
                // Note: if the RSA parameters are not attached to the signing key,
                // extract them by calling ExportParameters on the RSA instance.
                var parameters = rsaSecurityKey.Parameters;
                if (parameters.Modulus is null)
                {
                    parameters = rsaSecurityKey.Rsa.ExportParameters(includePrivateParameters: false);

                    Debug.Assert(parameters.Modulus is not null, SR.GetResourceString(SR.ID4003));
                }

                // Only use the 40 first chars of the base64url-encoded modulus.
                var identifier = Base64UrlEncoder.Encode(parameters.Modulus);
                return identifier[..Math.Min(identifier.Length, 40)].ToUpperInvariant();
            }

            if (key is ECDsaSecurityKey ecsdaSecurityKey)
            {
                // Extract the ECDSA parameters from the signing credentials.
                var parameters = ecsdaSecurityKey.ECDsa.ExportParameters(includePrivateParameters: false);

                Debug.Assert(parameters.Q.X is not null, SR.GetResourceString(SR.ID4004));

                // Only use the 40 first chars of the base64url-encoded X coordinate.
                var identifier = Base64UrlEncoder.Encode(parameters.Q.X);
                return identifier[..Math.Min(identifier.Length, 40)].ToUpperInvariant();
            }

            return null;
        }

        static string ComputeDefaultRegistrationId(OpenIddictClientRegistration registration)
        {
            Debug.Assert(registration.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));

            using var algorithm = SHA256.Create();

            TransformBlock(algorithm, registration.Issuer.AbsoluteUri);

            if (!string.IsNullOrEmpty(registration.ProviderName))
            {
                TransformBlock(algorithm, registration.ProviderName);
            }

            algorithm.TransformFinalBlock([], 0, 0);

            return Base64UrlEncoder.Encode(algorithm.Hash);

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            static void TransformBlock(HashAlgorithm algorithm, string input)
            {
                var buffer = Encoding.UTF8.GetBytes(input);
                algorithm.TransformBlock(buffer, 0, buffer.Length, outputBuffer: null, outputOffset: 0);
            }
        }
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, OpenIddictClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var builder = new ValidateOptionsResultBuilder();

        if (options.JsonWebTokenHandler is null)
        {
            builder.AddError(SR.GetResourceString(SR.ID0075));
        }

        foreach (var registration in options.Registrations)
        {
            if (string.IsNullOrEmpty(registration.RegistrationId))
            {
                builder.AddError(SR.GetResourceString(SR.ID0521));
            }

            // Ensure the registration identifier doesn't contain U+001E or U+001F separators as they are
            // used by the System.Net.Http integration to separate properties in the HTTP client names.
            else if (registration.RegistrationId.Any(static character => character is '\u001e' or '\u001f'))
            {
                builder.AddError(SR.GetResourceString(SR.ID0455));
            }

            if (registration.Issuer is null)
            {
                builder.AddError(string.IsNullOrEmpty(registration.ProviderType)
                    ? SR.GetResourceString(SR.ID0405)
                    : SR.GetResourceString(SR.ID0411));
            }

            else if (!registration.Issuer.IsAbsoluteUri || OpenIddictHelpers.IsImplicitFileUri(registration.Issuer))
            {
                builder.AddError(SR.GetResourceString(SR.ID0136));
            }

            else if (!string.IsNullOrEmpty(registration.Issuer.Fragment) || !string.IsNullOrEmpty(registration.Issuer.Query))
            {
                builder.AddError(SR.GetResourceString(SR.ID0137));
            }

            // If an issuer was attached to the static configuration, ensure it matches the issuer specified in the client registration.
            if (registration.Configuration?.Issuer is not null && registration.Configuration.Issuer != registration.Issuer)
            {
                builder.AddError(SR.GetResourceString(SR.ID0395));
            }

            if (registration.ConfigurationManager is null)
            {
                builder.AddError(SR.GetResourceString(SR.ID0522));
            }

            // If a non-static configuration manager is used, ensure that the required discovery handlers are registered.
            else if (!typeof(StaticConfigurationManager<OpenIddictConfiguration>).IsAssignableFrom(registration.ConfigurationManager.GetType()) &&
                    (!options.Handlers.Exists(static descriptor => descriptor.ContextType == typeof(ApplyConfigurationRequestContext)) ||
                     !options.Handlers.Exists(static descriptor => descriptor.ContextType == typeof(ApplyJsonWebKeySetRequestContext))))
            {
                builder.AddError(SR.GetResourceString(SR.ID0313));
            }
        }

        // Ensure at least one flow has been enabled.
        if (options.GrantTypes.Count is 0 && options.ResponseTypes.Count is 0)
        {
            builder.AddError(SR.GetResourceString(SR.ID0076));
        }

        // Ensure endpoint URIs are unique across endpoints.
        if (!ValidateUniqueEndpointUris(options))
        {
            builder.AddError(SR.GetResourceString(SR.ID0285));
        }

        // Ensure the redirection endpoint has been enabled when the authorization code or implicit grants are supported.
        if (options.RedirectionEndpointUris.Count is 0 && (options.GrantTypes.Contains(GrantTypes.AuthorizationCode) ||
                                                           options.GrantTypes.Contains(GrantTypes.Implicit)))
        {
            builder.AddError(SR.GetResourceString(SR.ID0356));
        }

        // Ensure the grant types/response types configuration is consistent.
        foreach (var type in options.ResponseTypes)
        {
            var types = type.Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
            if (types.Contains(ResponseTypes.Code) && !options.GrantTypes.Contains(GrantTypes.AuthorizationCode))
            {
                builder.AddError(SR.FormatID0281(ResponseTypes.Code));
            }

            if (types.Contains(ResponseTypes.IdToken) && !options.GrantTypes.Contains(GrantTypes.Implicit))
            {
                builder.AddError(SR.FormatID0282(ResponseTypes.IdToken));
            }

            if (types.Contains(ResponseTypes.Token) && !options.GrantTypes.Contains(GrantTypes.Implicit))
            {
                builder.AddError(SR.FormatID0282(ResponseTypes.Token));
            }
        }

        // When the redirection or post-logout redirection endpoint has been enabled, ensure signing
        // and encryption credentials have been provided as they are required to protect state tokens.
        if (options.RedirectionEndpointUris.Count is not 0 || options.PostLogoutRedirectionEndpointUris.Count is not 0)
        {
            if (options.EncryptionCredentials.Count is 0)
            {
                builder.AddError(SR.GetResourceString(SR.ID0357));
            }

            if (options.SigningCredentials.Count is 0)
            {
                builder.AddError(SR.GetResourceString(SR.ID0358));
            }
        }

        // Ensure registration identifiers are not used in multiple client registrations.
        //
        // Note: a string comparer ignoring casing is deliberately used to prevent two
        // registrations using the same identifier with a different casing from being added.
        if (options.Registrations.Count != options.Registrations.Select(registration => registration.RegistrationId)
                                                                .Distinct(StringComparer.OrdinalIgnoreCase)
                                                                .Count())
        {
            builder.AddError(SR.GetResourceString(SR.ID0347));
        }

        return builder.Build();

        static bool ValidateUniqueEndpointUris(OpenIddictClientOptions options)
        {
            var uris = options.RedirectionEndpointUris.Distinct()
                .Concat(options.PostLogoutRedirectionEndpointUris.Distinct())
                .ToList();

            return uris.Count == uris.Distinct().Count();
        }
    }
}
