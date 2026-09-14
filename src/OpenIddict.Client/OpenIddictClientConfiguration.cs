/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Text;
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
            ConfigureRegistration(_provider, options, registration);
        }

        // Implicitly add the redirect_uri attached to the client registrations
        // to the list of redirection endpoints URIs if they haven't been added.
        options.RedirectionEndpointUris.AddRange(options.Registrations
            .Where(static registration => registration.RedirectUri is not null)
            .Select(static registration => registration.RedirectUri!)
            .Where(uri => !options.RedirectionEndpointUris.Contains(uri))
            .Distinct()
            .ToList());

        // Implicitly add the post_logout_redirect_uri attached to the client registrations
        // to the list of post-logout redirection endpoints URIs if they haven't been added.
        options.PostLogoutRedirectionEndpointUris.AddRange(options.Registrations
            .Where(static registration => registration.PostLogoutRedirectUri is not null)
            .Select(static registration => registration.PostLogoutRedirectUri!)
            .Where(uri => !options.PostLogoutRedirectionEndpointUris.Contains(uri))
            .Distinct()
            .ToList());

        // Implicitly add the back-channel and front-channel logout URIs attached to the
        // client registrations to the list of logout endpoints URIs if they haven't been added.
        options.BackchannelLogoutEndpointUris.AddRange(options.Registrations
            .Where(static registration => registration.BackchannelLogoutUri is not null)
            .Select(static registration => registration.BackchannelLogoutUri!)
            .Where(uri => !options.BackchannelLogoutEndpointUris.Contains(uri))
            .Distinct()
            .ToList());

        options.FrontchannelLogoutEndpointUris.AddRange(options.Registrations
            .Where(static registration => registration.FrontchannelLogoutUri is not null)
            .Select(static registration => registration.FrontchannelLogoutUri!)
            .Where(uri => !options.FrontchannelLogoutEndpointUris.Contains(uri))
            .Distinct()
            .ToList());

        // Sort the handlers collection using the order associated with each handler.
        options.Handlers.Sort((left, right) => left.Order.CompareTo(right.Order));

        var now = options.TimeProvider.GetUtcNow().LocalDateTime;

        // Sort the encryption and signing credentials.
        options.EncryptionCredentials.Sort((left, right) => Compare(left.Key, right.Key, now));
        options.SigningCredentials.Sort((left, right) => Compare(left.Key, right.Key, now));

        // Generate a key identifier for the encryption/signing keys that don't already have one.
        foreach (var key in options.EncryptionCredentials.Select(static credentials => credentials.Key)
            .Concat(options.SigningCredentials.Select(static credentials => credentials.Key))
            .Where(static key => string.IsNullOrEmpty(key.KeyId)))
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

            return key switch
            {
                X509SecurityKey  value => value.Certificate.Thumbprint,
                RsaSecurityKey   value => GetRsaSecurityKeyIdentifier(value),
                ECDsaSecurityKey value => GetEcdsaSecurityKeyIdentifier(value),
                MlDsaSecurityKey value => GetMLDsaSecurityKeyIdentifier(value),

                _ => null
            };

            static string GetEcdsaSecurityKeyIdentifier(ECDsaSecurityKey key)
            {
                var parameters = key.ECDsa.ExportParameters(includePrivateParameters: false);

                Debug.Assert(parameters.Q.X is not null, SR.GetResourceString(SR.ID4004));

                // Only use the 40 first chars of the base64url-encoded X coordinate.
                var identifier = Base64Url.EncodeToString(parameters.Q.X);
                return identifier[.. Math.Min(identifier.Length, 40)].ToUpperInvariant();
            }

            static string GetMLDsaSecurityKeyIdentifier(MlDsaSecurityKey key)
            {
                // Only use the 40 first chars of the base64url-encoded SHA256 of the ML-DSA public key.
                var identifier = Base64Url.EncodeToString(SHA256.HashData(key.MLDsa.ExportMLDsaPublicKey()));
                return identifier[.. Math.Min(identifier.Length, 40)].ToUpperInvariant();
            }

            static string GetRsaSecurityKeyIdentifier(RsaSecurityKey key)
            {
                // Note: if the RSA parameters are not attached to the signing key,
                // extract them by calling ExportParameters on the RSA instance.
                var parameters = key.Parameters;
                if (parameters.Modulus is null)
                {
                    parameters = key.Rsa.ExportParameters(includePrivateParameters: false);

                    Debug.Assert(parameters.Modulus is not null, SR.GetResourceString(SR.ID4003));
                }

                // Only use the 40 first chars of the base64url-encoded modulus.
                var identifier = Base64Url.EncodeToString(parameters.Modulus);
                return identifier[.. Math.Min(identifier.Length, 40)].ToUpperInvariant();
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
            ValidateRegistration(options, registration, builder);
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

        if (options.LogoutTokenMaximumAge < TimeSpan.Zero)
        {
            builder.AddError(SR.GetResourceString(SR.ID0765));
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
        if (options.Registrations.Count != options.Registrations.Select(static registration => registration.RegistrationId)
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
                .Concat(options.BackchannelLogoutEndpointUris.Distinct())
                .Concat(options.FrontchannelLogoutEndpointUris.Distinct())
                .ToList();

            return uris.Count == uris.Distinct().Count();
        }
    }

    /// <summary>
    /// Populates the default properties of the specified client registration (e.g registration
    /// identifier, client type or configuration manager), if they were not explicitly set.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    /// <param name="options">The client options.</param>
    /// <param name="registration">The client registration.</param>
    internal static void ConfigureRegistration(IServiceProvider provider,
        OpenIddictClientOptions options, OpenIddictClientRegistration registration)
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

        // The FAPI 2.0 message signing profile includes the FAPI 2.0 security profile.
        if (registration.EnableFapi2MessageSigningProfile)
        {
            registration.EnableFapi2SecurityProfile = true;
            registration.UseSignedRequestObjects = true;
            registration.RequireJsonWebTokenIntrospectionResponses = true;
        }

        if (registration.EnableFapi2SecurityProfile)
        {
            ConfigureFapi2SecurityProfile(options, registration);
        }

        // If DPoP token binding was enabled and no DPoP key was attached to the registration, generate an ephemeral key.
        if (options.TokenBindingMethods.Contains(TokenBindingMethods.Private.DPoP) && registration.DPoPSigningCredentials is null &&
           (registration.TokenBindingMethods.Count is 0 || registration.TokenBindingMethods.Contains(TokenBindingMethods.Private.DPoP)))
        {
            registration.DPoPSigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)), SecurityAlgorithms.EcdsaSha256);
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
                    new OpenIddictClientRetriever(provider.GetRequiredService<OpenIddictClientService>(), registration))
                {
                    AutomaticRefreshInterval = ConfigurationManager<OpenIddictConfiguration>.DefaultAutomaticRefreshInterval,
                    RefreshInterval = ConfigurationManager<OpenIddictConfiguration>.DefaultRefreshInterval
                };
            }
        }
    }

    /// <summary>
    /// Populates the settings of a client registration enforcing the FAPI 2.0 security profile
    /// with the values allowed by the profile, when they were not explicitly set.
    /// </summary>
    /// <param name="options">The client options.</param>
    /// <param name="registration">The client registration.</param>
    private static void ConfigureFapi2SecurityProfile(OpenIddictClientOptions options, OpenIddictClientRegistration registration)
    {
        // See https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1 (item 6).
        if (registration.ClientAuthenticationMethods.Count is 0)
        {
            registration.ClientAuthenticationMethods.UnionWith(OpenIddictClientFapi2Profile.ClientAuthenticationMethods);
        }

        // See https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.3.1 (item 1).
        if (registration.CodeChallengeMethods.Count is 0)
        {
            registration.CodeChallengeMethods.Add(CodeChallengeMethods.Sha256);
        }

        // The implicit and password grants are not allowed by the profile (section 5.3.2.2, item 1 and section 5.3.2.1).
        if (registration.GrantTypes.Count is 0)
        {
            registration.GrantTypes.UnionWith(options.GrantTypes.Where(static type =>
                type is not (GrantTypes.Implicit or GrantTypes.Password)));
        }

        // Only response_type=code is allowed by the profile (section 5.3.2.2, item 1).
        if (registration.ResponseTypes.Count is 0)
        {
            registration.ResponseTypes.Add(ResponseTypes.Code);
        }

        // Access tokens must be sender-constrained using DPoP or mTLS (section 5.3.3.1, item 2).
        if (registration.TokenBindingMethods.Count is 0)
        {
            registration.TokenBindingMethods.Add(TokenBindingMethods.Private.DPoP);
            registration.TokenBindingMethods.Add(TokenBindingMethods.Private.TlsClientCertificate);
        }

        // See https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1.
        if (registration.IntrospectionResponseSigningAlgorithms.Count is 0)
        {
            registration.IntrospectionResponseSigningAlgorithms.UnionWith(OpenIddictClientFapi2Profile.SigningAlgorithms);
        }

        registration.TokenValidationParameters.ValidAlgorithms ??= [.. OpenIddictClientFapi2Profile.SigningAlgorithms];

        // RSASSA-PKCS1-v1_5 is not allowed by the profile but the same RSA keys can be used with RSASSA-PSS:
        // to support the credentials registered using the default RS256 algorithm, PS256 is used instead.
        for (var index = 0; index < registration.SigningCredentials.Count; index++)
        {
            var credentials = registration.SigningCredentials[index];
            if (credentials.Key is not SymmetricSecurityKey && credentials.Algorithm is
                SecurityAlgorithms.RsaSha256 or SecurityAlgorithms.RsaSha256Signature or
                SecurityAlgorithms.RsaSha384 or SecurityAlgorithms.RsaSha384Signature or
                SecurityAlgorithms.RsaSha512 or SecurityAlgorithms.RsaSha512Signature)
            {
                registration.SigningCredentials[index] = new SigningCredentials(credentials.Key, SecurityAlgorithms.RsaSsaPssSha256);
            }
        }
    }

    /// <summary>
    /// Validates the settings of a client registration enforcing the FAPI 2.0 security profile.
    /// </summary>
    /// <param name="options">The client options.</param>
    /// <param name="registration">The client registration.</param>
    /// <param name="builder">The builder used to collect the validation errors.</param>
    private static void ValidateFapi2SecurityProfile(OpenIddictClientOptions options,
        OpenIddictClientRegistration registration, ValidateOptionsResultBuilder builder)
    {
        // Only confidential clients are allowed (section 5.3.2.1, item 3).
        if (registration.ClientType is not ClientTypes.Confidential)
        {
            builder.AddError(SR.FormatID0973(registration.RegistrationId));
        }

        // Pushed authorization requests are required (section 5.3.2.2, item 5).
        if (registration.DisablePushedAuthorizationRequests)
        {
            builder.AddError(SR.FormatID0974(registration.RegistrationId));
        }

        // Only S256 is allowed (section 5.3.2.2, item 5).
        if (registration.CodeChallengeMethods.Any(static method => method is not CodeChallengeMethods.Sha256))
        {
            builder.AddError(SR.FormatID0975(registration.RegistrationId));
        }

        if (registration.ClientAuthenticationMethods.Any(static method =>
            !OpenIddictClientFapi2Profile.ClientAuthenticationMethods.Contains(method, StringComparer.Ordinal)))
        {
            builder.AddError(SR.FormatID0976(registration.RegistrationId));
        }

        if (registration.GrantTypes.Contains(GrantTypes.Implicit) || registration.GrantTypes.Contains(GrantTypes.Password) ||
            registration.ResponseTypes.Any(static type => type is not ResponseTypes.Code))
        {
            builder.AddError(SR.FormatID0977(registration.RegistrationId));
        }

        // Ensure at least one sender-constraining mechanism is enabled both globally and for the registration.
        if (!registration.TokenBindingMethods.Any(method =>
            OpenIddictClientFapi2Profile.TokenBindingMethods.Contains(method, StringComparer.Ordinal) &&
            options.TokenBindingMethods.Contains(method)))
        {
            builder.AddError(SR.FormatID0978(registration.RegistrationId));
        }

        // Ensure the asymmetric keys used to sign client assertions, request objects
        // and DPoP proofs use an algorithm allowed by the profile (section 5.4.1).
        if (registration.SigningCredentials.Exists(static credentials => credentials.Key is AsymmetricSecurityKey &&
                !OpenIddictClientFapi2Profile.IsSigningAlgorithmAllowed(credentials.Algorithm)) ||
            (registration.DPoPSigningCredentials is SigningCredentials dpop &&
                !OpenIddictClientFapi2Profile.IsSigningAlgorithmAllowed(dpop.Algorithm)))
        {
            builder.AddError(SR.FormatID0979(registration.RegistrationId));
        }

        // Client secrets cannot be used with the profile: at least one asymmetric
        // key (or X.509 certificate) is required to authenticate the client.
        if (!registration.SigningCredentials.Exists(static credentials => credentials.Key is AsymmetricSecurityKey))
        {
            builder.AddError(SR.FormatID0980(registration.RegistrationId));
        }
    }

    /// <summary>
    /// Validates the specified client registration.
    /// </summary>
    /// <param name="options">The client options.</param>
    /// <param name="registration">The client registration.</param>
    /// <param name="builder">The builder used to collect the validation errors.</param>
    internal static void ValidateRegistration(OpenIddictClientOptions options,
        OpenIddictClientRegistration registration, ValidateOptionsResultBuilder builder)
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

        if (registration.EnableFapi2SecurityProfile)
        {
            ValidateFapi2SecurityProfile(options, registration, builder);
        }
    }

    internal static string ComputeDefaultRegistrationId(OpenIddictClientRegistration registration)
    {
        Debug.Assert(registration.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));

        using var algorithm = SHA256.Create();

        TransformBlock(algorithm, registration.Issuer.AbsoluteUri);

        if (!string.IsNullOrEmpty(registration.ProviderName))
        {
            TransformBlock(algorithm, registration.ProviderName);
        }

        algorithm.TransformFinalBlock([], 0, 0);

        return Base64Url.EncodeToString(algorithm.Hash);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static void TransformBlock(HashAlgorithm algorithm, string input)
        {
            var buffer = Encoding.UTF8.GetBytes(input);
            algorithm.TransformBlock(buffer, 0, buffer.Length, outputBuffer: null, outputOffset: 0);
        }
    }
}
