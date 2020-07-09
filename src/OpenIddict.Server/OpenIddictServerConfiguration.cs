/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using JetBrains.Annotations;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;

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
                throw new InvalidOperationException("The security token handler cannot be null.");
            }

            // Ensure at least one flow has been enabled.
            if (options.GrantTypes.Count == 0)
            {
                throw new InvalidOperationException("At least one OAuth 2.0/OpenID Connect flow must be enabled.");
            }

            // Ensure the authorization endpoint has been enabled when
            // the authorization code or implicit grants are supported.
            if (options.AuthorizationEndpointUris.Count == 0 && (options.GrantTypes.Contains(GrantTypes.AuthorizationCode) ||
                                                                 options.GrantTypes.Contains(GrantTypes.Implicit)))
            {
                throw new InvalidOperationException(new StringBuilder()
                    .Append("The authorization endpoint must be enabled to use the authorization code and implicit flows.")
                    .ToString());
            }

            // Ensure the device endpoint has been enabled when the device grant is supported.
            if (options.DeviceEndpointUris.Count == 0 && options.GrantTypes.Contains(GrantTypes.DeviceCode))
            {
                throw new InvalidOperationException("The device endpoint must be enabled to use the device flow.");
            }

            // Ensure the token endpoint has been enabled when the authorization code,
            // client credentials, device, password or refresh token grants are supported.
            if (options.TokenEndpointUris.Count == 0 && (options.GrantTypes.Contains(GrantTypes.AuthorizationCode) ||
                                                         options.GrantTypes.Contains(GrantTypes.ClientCredentials) ||
                                                         options.GrantTypes.Contains(GrantTypes.DeviceCode) ||
                                                         options.GrantTypes.Contains(GrantTypes.Password) ||
                                                         options.GrantTypes.Contains(GrantTypes.RefreshToken)))
            {
                throw new InvalidOperationException(new StringBuilder()
                    .Append("The token endpoint must be enabled to use the authorization code, ")
                    .Append("client credentials, device, password and refresh token flows.")
                    .ToString());
            }

            // Ensure the verification endpoint has been enabled when the device grant is supported.
            if (options.VerificationEndpointUris.Count == 0 && options.GrantTypes.Contains(GrantTypes.DeviceCode))
            {
                throw new InvalidOperationException("The verification endpoint must be enabled to use the device flow.");
            }

            if (options.DisableTokenStorage)
            {
                if (options.DeviceEndpointUris.Count != 0 || options.VerificationEndpointUris.Count != 0)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("The device and verification endpoints cannot be enabled when token storage is disabled.")
                        .ToString());
                }

                if (options.RevocationEndpointUris.Count != 0)
                {
                    throw new InvalidOperationException("The revocation endpoint cannot be enabled when token storage is disabled.");
                }

                if (options.UseReferenceAccessTokens || options.UseReferenceRefreshTokens)
                {
                    throw new InvalidOperationException("Reference tokens cannot be used when disabling token storage.");
                }

                if (!options.DisableSlidingRefreshTokenExpiration && !options.UseRollingRefreshTokens)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("Sliding expiration must be disabled when turning off token storage if rolling tokens are not used.")
                        .ToString());
                }
            }

            if (options.EncryptionCredentials.Count == 0)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("At least one encryption key must be registered in the OpenIddict server options.")
                    .Append("Consider registering a certificate using 'services.AddOpenIddict().AddServer().AddEncryptionCertificate()' ")
                    .Append("or 'services.AddOpenIddict().AddServer().AddDevelopmentEncryptionCertificate()' or call ")
                    .Append("'services.AddOpenIddict().AddServer().AddEphemeralEncryptionKey()' to use an ephemeral key.")
                    .ToString());
            }

            if (!options.SigningCredentials.Any(credentials => credentials.Key is AsymmetricSecurityKey))
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("At least one asymmetric signing key must be registered in the OpenIddict server options.")
                    .Append("Consider registering a certificate using 'services.AddOpenIddict().AddServer().AddSigningCertificate()' ")
                    .Append("or 'services.AddOpenIddict().AddServer().AddDevelopmentSigningCertificate()' or call ")
                    .Append("'services.AddOpenIddict().AddServer().AddEphemeralSigningKey()' to use an ephemeral key.")
                    .ToString());
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
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No custom authorization request validation handler was found. When enabling the degraded mode, ")
                        .Append("a custom 'IOpenIddictServerHandler<ValidateAuthorizationRequestContext>' must be implemented ")
                        .Append("to validate authorization requests (e.g to ensure the client_id and redirect_uri are valid).")
                        .ToString());
                }

                if (options.DeviceEndpointUris.Count != 0 && !options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateDeviceRequestContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No custom device request validation handler was found. When enabling the degraded mode, ")
                        .Append("a custom 'IOpenIddictServerHandler<ValidateDeviceRequestContext>' must be implemented ")
                        .Append("to validate device requests (e.g to ensure the client_id and client_secret are valid).")
                        .ToString());
                }

                if (options.IntrospectionEndpointUris.Count != 0 && !options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateIntrospectionRequestContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No custom introspection request validation handler was found. When enabling the degraded mode, ")
                        .Append("a custom 'IOpenIddictServerHandler<ValidateIntrospectionRequestContext>' must be implemented ")
                        .Append("to validate introspection requests (e.g to ensure the client_id and client_secret are valid).")
                        .ToString());
                }

                if (options.LogoutEndpointUris.Count != 0 && !options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateLogoutRequestContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No custom logout request validation handler was found. When enabling the degraded mode, ")
                        .Append("a custom 'IOpenIddictServerHandler<ValidateLogoutRequestContext>' must be implemented ")
                        .Append("to validate logout requests (e.g to ensure the post_logout_redirect_uri is valid).")
                        .ToString());
                }

                if (options.RevocationEndpointUris.Count != 0 && !options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateRevocationRequestContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No custom revocation request validation handler was found. When enabling the degraded mode, ")
                        .Append("a custom 'IOpenIddictServerHandler<ValidateRevocationRequestContext>' must be implemented ")
                        .Append("to validate revocation requests (e.g to ensure the client_id and client_secret are valid).")
                        .ToString());
                }

                if (options.TokenEndpointUris.Count != 0 && !options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateTokenRequestContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No custom token request validation handler was found. When enabling the degraded mode, ")
                        .Append("a custom 'IOpenIddictServerHandler<ValidateTokenRequestContext>' must be implemented ")
                        .Append("to validate token requests (e.g to ensure the client_id and client_secret are valid).")
                        .ToString());
                }

                if (options.VerificationEndpointUris.Count != 0 && !options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateVerificationRequestContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No custom verification request validation handler was found. When enabling the degraded mode, ")
                        .Append("a custom 'IOpenIddictServerHandler<ValidateVerificationRequestContext>' must be implemented ")
                        .Append("to validate verification requests (e.g to ensure the user_code is valid).")
                        .ToString());
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
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("No custom verification authentication handler was found. When enabling the degraded mode, ")
                            .Append("a custom 'IOpenIddictServerHandler<ProcessAuthenticationContext>' must be implemented ")
                            .Append("to validate device and user codes (e.g by retrieving them from a database).")
                            .ToString());
                    }

                    if (!options.Handlers.Any(
                        descriptor => descriptor.ContextType == typeof(ProcessSignInContext) &&
                                      descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                      descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("No custom verification sign-in handler was found. When enabling the degraded mode, ")
                            .Append("a custom 'IOpenIddictServerHandler<ProcessSignInContext>' must be implemented ")
                            .Append("to generate device and user codes and storing them in a database, if applicable.")
                            .ToString());
                    }
                }
            }

            // Sort the handlers collection using the order associated with each handler.
            options.Handlers.Sort((left, right) => left.Order.CompareTo(right.Order));

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

                        Debug.Assert(parameters.Modulus != null,
                            "A null modulus shouldn't be returned by RSA.ExportParameters().");
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

                    Debug.Assert(parameters.Q.X != null,
                        "Invalid coordinates shouldn't be returned by ECDsa.ExportParameters().");

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
