/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Linq;
using JetBrains.Annotations;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using SR = OpenIddict.Abstractions.Resources.OpenIddictResources;

namespace OpenIddict.Server
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict server configuration is valid.
    /// </summary>
    public class OpenIddictServerConfiguration : IPostConfigureOptions<OpenIddictServerOptions>
    {
        /// <summary>
        /// Populates the default OpenIddict server options and ensures
        /// that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The name of the options instance to configure, if applicable.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([CanBeNull] string name, [NotNull] OpenIddictServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (options.JsonWebTokenHandler == null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1074));
            }

            // Ensure at least one flow has been enabled.
            if (options.GrantTypes.Count == 0)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1075));
            }

            // Ensure the authorization endpoint has been enabled when
            // the authorization code or implicit grants are supported.
            if (options.AuthorizationEndpointUris.Count == 0 && (options.GrantTypes.Contains(GrantTypes.AuthorizationCode) ||
                                                                 options.GrantTypes.Contains(GrantTypes.Implicit)))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1076));
            }

            // Ensure the device endpoint has been enabled when the device grant is supported.
            if (options.DeviceEndpointUris.Count == 0 && options.GrantTypes.Contains(GrantTypes.DeviceCode))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1077));
            }

            // Ensure the token endpoint has been enabled when the authorization code,
            // client credentials, device, password or refresh token grants are supported.
            if (options.TokenEndpointUris.Count == 0 && (options.GrantTypes.Contains(GrantTypes.AuthorizationCode) ||
                                                         options.GrantTypes.Contains(GrantTypes.ClientCredentials) ||
                                                         options.GrantTypes.Contains(GrantTypes.DeviceCode) ||
                                                         options.GrantTypes.Contains(GrantTypes.Password) ||
                                                         options.GrantTypes.Contains(GrantTypes.RefreshToken)))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1078));
            }

            // Ensure the verification endpoint has been enabled when the device grant is supported.
            if (options.VerificationEndpointUris.Count == 0 && options.GrantTypes.Contains(GrantTypes.DeviceCode))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1079));
            }

            if (options.DisableTokenStorage)
            {
                if (options.DeviceEndpointUris.Count != 0 || options.VerificationEndpointUris.Count != 0)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1080));
                }

                if (options.RevocationEndpointUris.Count != 0)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1081));
                }

                if (options.UseReferenceAccessTokens || options.UseReferenceRefreshTokens)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1082));
                }

                if (!options.DisableSlidingRefreshTokenExpiration && !options.UseRollingRefreshTokens)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1083));
                }
            }

            if (options.EncryptionCredentials.Count == 0)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1084));
            }

            if (!options.SigningCredentials.Any(credentials => credentials.Key is AsymmetricSecurityKey))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1085));
            }

            // If all the registered encryption credentials are backed by a X.509 certificate, at least one of them must be valid.
            if (options.EncryptionCredentials.All(credentials => credentials.Key is X509SecurityKey x509SecurityKey &&
                   (x509SecurityKey.Certificate.NotBefore > DateTime.Now || x509SecurityKey.Certificate.NotAfter < DateTime.Now)))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1086));
            }

            // If all the registered signing credentials are backed by a X.509 certificate, at least one of them must be valid.
            if (options.SigningCredentials.All(credentials => credentials.Key is X509SecurityKey x509SecurityKey &&
                   (x509SecurityKey.Certificate.NotBefore > DateTime.Now || x509SecurityKey.Certificate.NotAfter < DateTime.Now)))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1087));
            }

            if (options.EnableDegradedMode)
            {
                // If the degraded mode was enabled, ensure custom validation handlers
                // have been registered for the endpoints that require manual validation.

                if (options.AuthorizationEndpointUris.Count != 0 && !options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateAuthorizationRequestContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1088));
                }

                if (options.DeviceEndpointUris.Count != 0 && !options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateDeviceRequestContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1089));
                }

                if (options.IntrospectionEndpointUris.Count != 0 && !options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateIntrospectionRequestContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1090));
                }

                if (options.LogoutEndpointUris.Count != 0 && !options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateLogoutRequestContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1091));
                }

                if (options.RevocationEndpointUris.Count != 0 && !options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateRevocationRequestContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1092));
                }

                if (options.TokenEndpointUris.Count != 0 && !options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateTokenRequestContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1093));
                }

                if (options.VerificationEndpointUris.Count != 0 && !options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateVerificationRequestContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1094));
                }

                // If the degraded mode was enabled, ensure custom authentication/sign-in handlers
                // have been registered to deal with device/user codes validation and generation.

                if (options.GrantTypes.Contains(GrantTypes.DeviceCode))
                {
                    if (!options.Handlers.Any(
                        descriptor => descriptor.ContextType == typeof(ProcessAuthenticationContext) &&
                                      descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                      descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1095));
                    }

                    if (!options.Handlers.Any(
                        descriptor => descriptor.ContextType == typeof(ProcessSignInContext) &&
                                      descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                      descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1096));
                    }
                }
            }

            // Sort the handlers collection using the order associated with each handler.
            options.Handlers.Sort((left, right) => left.Order.CompareTo(right.Order));

            // Sort the encryption and signing credentials.
            options.EncryptionCredentials.Sort((left, right) => Compare(left.Key, right.Key));
            options.SigningCredentials.Sort((left, right) => Compare(left.Key, right.Key));

            // Automatically add the offline_access scope if the refresh token grant has been enabled.
            if (options.GrantTypes.Contains(GrantTypes.RefreshToken))
            {
                options.Scopes.Add(Scopes.OfflineAccess);
            }

            if (options.GrantTypes.Contains(GrantTypes.AuthorizationCode))
            {
                options.CodeChallengeMethods.Add(CodeChallengeMethods.Sha256);

                options.ResponseTypes.Add(ResponseTypes.Code);
            }

            if (options.GrantTypes.Contains(GrantTypes.Implicit))
            {
                options.ResponseTypes.Add(ResponseTypes.IdToken);
                options.ResponseTypes.Add(ResponseTypes.IdToken + ' ' + ResponseTypes.Token);
                options.ResponseTypes.Add(ResponseTypes.Token);
            }

            if (options.GrantTypes.Contains(GrantTypes.AuthorizationCode) && options.GrantTypes.Contains(GrantTypes.Implicit))
            {
                options.ResponseTypes.Add(ResponseTypes.Code + ' ' + ResponseTypes.IdToken);
                options.ResponseTypes.Add(ResponseTypes.Code + ' ' + ResponseTypes.IdToken + ' ' + ResponseTypes.Token);
                options.ResponseTypes.Add(ResponseTypes.Code + ' ' + ResponseTypes.Token);
            }

            if (options.ResponseTypes.Count != 0)
            {
                options.ResponseModes.Add(ResponseModes.FormPost);
                options.ResponseModes.Add(ResponseModes.Fragment);

                if (options.ResponseTypes.Contains(ResponseTypes.Code))
                {
                    options.ResponseModes.Add(ResponseModes.Query);
                }
            }

            foreach (var key in options.EncryptionCredentials
                .Select(credentials => credentials.Key)
                .Concat(options.SigningCredentials.Select(credentials => credentials.Key)))
            {
                if (!string.IsNullOrEmpty(key.KeyId))
                {
                    continue;
                }

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

            static int Compare(SecurityKey left, SecurityKey right) => (left, right) switch
            {
                // If the two keys refer to the same instances, return 0.
                (SecurityKey first, SecurityKey second) when ReferenceEquals(first, second) => 0,

                // If one of the keys is a symmetric key, prefer it to the other one.
                (SymmetricSecurityKey _, SymmetricSecurityKey _) => 0,
                (SymmetricSecurityKey _, SecurityKey _)          => -1,
                (SecurityKey _, SymmetricSecurityKey _)          => 1,

                // If one of the keys is backed by a X.509 certificate, don't prefer it if it's not valid yet.
                (X509SecurityKey first, SecurityKey _)  when first.Certificate.NotBefore  > DateTime.Now => 1,
                (SecurityKey _, X509SecurityKey second) when second.Certificate.NotBefore > DateTime.Now => 1,

                // If the two keys are backed by a X.509 certificate, prefer the one with the furthest expiration date.
                (X509SecurityKey first, X509SecurityKey second) => -first.Certificate.NotAfter.CompareTo(second.Certificate.NotAfter),

                // If one of the keys is backed by a X.509 certificate, prefer the X.509 security key.
                (X509SecurityKey _, SecurityKey _) => -1,
                (SecurityKey _, X509SecurityKey _) => 1,

                // If the two keys are not backed by a X.509 certificate, none should be preferred to the other.
                (SecurityKey _, SecurityKey _) => 0
            };

            static string GetKeyIdentifier(SecurityKey key)
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
                    if (parameters.Modulus == null)
                    {
                        parameters = rsaSecurityKey.Rsa.ExportParameters(includePrivateParameters: false);

                        Debug.Assert(parameters.Modulus != null, SR.GetResourceString(SR.ID5003));
                    }

                    // Only use the 40 first chars of the base64url-encoded modulus.
                    var identifier = Base64UrlEncoder.Encode(parameters.Modulus);
                    return identifier.Substring(0, Math.Min(identifier.Length, 40)).ToUpperInvariant();
                }

#if SUPPORTS_ECDSA
                if (key is ECDsaSecurityKey ecsdaSecurityKey)
                {
                    // Extract the ECDSA parameters from the signing credentials.
                    var parameters = ecsdaSecurityKey.ECDsa.ExportParameters(includePrivateParameters: false);

                    Debug.Assert(parameters.Q.X != null, SR.GetResourceString(SR.ID5004));

                    // Only use the 40 first chars of the base64url-encoded X coordinate.
                    var identifier = Base64UrlEncoder.Encode(parameters.Q.X);
                    return identifier.Substring(0, Math.Min(identifier.Length, 40)).ToUpperInvariant();
                }
#endif

                return null;
            }
        }
    }
}
