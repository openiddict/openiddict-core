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
        /// <param name="name">The authentication scheme associated with the handler instance.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([CanBeNull] string name, [NotNull] OpenIddictServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
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
                throw new InvalidOperationException("The authorization endpoint must be enabled to use the authorization code and implicit flows.");
            }

            // Ensure the token endpoint has been enabled when the authorization code,
            // client credentials, password or refresh token grants are supported.
            if (options.TokenEndpointUris.Count == 0 && (options.GrantTypes.Contains(GrantTypes.AuthorizationCode) ||
                                                         options.GrantTypes.Contains(GrantTypes.ClientCredentials) ||
                                                         options.GrantTypes.Contains(GrantTypes.Password) ||
                                                         options.GrantTypes.Contains(GrantTypes.RefreshToken)))
            {
                throw new InvalidOperationException(
                    "The token endpoint must be enabled to use the authorization code, client credentials, password and refresh token flows.");
            }

            if (options.DisableTokenStorage && options.RevocationEndpointUris.Count != 0)
            {
                throw new InvalidOperationException("The revocation endpoint cannot be enabled when token storage is disabled.");
            }

            if (options.UseReferenceTokens && options.DisableTokenStorage)
            {
                throw new InvalidOperationException("Reference tokens cannot be used when disabling token storage.");
            }

            if (options.UseReferenceTokens && options.AccessTokenHandler != null)
            {
                throw new InvalidOperationException("Reference tokens cannot be used when configuring JWT as the access token format.");
            }

            if (options.UseSlidingExpiration && options.DisableTokenStorage && !options.UseRollingTokens)
            {
                throw new InvalidOperationException(
                    "Sliding expiration must be disabled when turning off token storage if rolling tokens are not used.");
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

            // If the degraded mode was enabled, ensure custom validation handlers
            // have been registered for the endpoints that require manual validation.
            if (options.EnableDegradedMode)
            {
                if (options.AuthorizationEndpointUris.Count != 0 && !options.CustomHandlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateAuthorizationRequestContext) &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No custom authorization request validation handler was found. When enabling the degraded mode, ")
                        .Append("a custom 'IOpenIddictServerHandler<ValidateAuthorizationRequestContext>' must be implemented ")
                        .Append("to validate authorization requests (e.g to ensure the client_id and redirect_uri are valid).")
                        .ToString());
                }

                if (options.IntrospectionEndpointUris.Count != 0 && !options.CustomHandlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateIntrospectionRequestContext) &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No custom introspection request validation handler was found. When enabling the degraded mode, ")
                        .Append("a custom 'IOpenIddictServerHandler<ValidateIntrospectionRequestContext>' must be implemented ")
                        .Append("to validate introspection requests (e.g to ensure the client_id and client_secret are valid).")
                        .ToString());
                }

                if (options.LogoutEndpointUris.Count != 0 && !options.CustomHandlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateLogoutRequestContext) &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No custom logout request validation handler was found. When enabling the degraded mode, ")
                        .Append("a custom 'IOpenIddictServerHandler<ValidateLogoutRequestContext>' must be implemented ")
                        .Append("to validate logout requests (e.g to ensure the post_logout_redirect_uri is valid).")
                        .ToString());
                }

                if (options.RevocationEndpointUris.Count != 0 && !options.CustomHandlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateRevocationRequestContext) &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No custom revocation request validation handler was found. When enabling the degraded mode, ")
                        .Append("a custom 'IOpenIddictServerHandler<ValidateRevocationRequestContext>' must be implemented ")
                        .Append("to validate revocation requests (e.g to ensure the client_id and client_secret are valid).")
                        .ToString());
                }

                if (options.TokenEndpointUris.Count != 0 && !options.CustomHandlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateTokenRequestContext) &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No custom token request validation handler was found. When enabling the degraded mode, ")
                        .Append("a custom 'IOpenIddictServerHandler<ValidateTokenRequestContext>' must be implemented ")
                        .Append("to validate token requests (e.g to ensure the client_id and client_secret are valid).")
                        .ToString());
                }
            }

            // Automatically add the offline_access scope if the refresh token grant has been enabled.
            if (options.GrantTypes.Contains(GrantTypes.RefreshToken))
            {
                options.Scopes.Add(Scopes.OfflineAccess);
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
