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

namespace OpenIddict.Validation
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict validation configuration is valid.
    /// </summary>
    public class OpenIddictValidationConfiguration : IPostConfigureOptions<OpenIddictValidationOptions>
    {
        /// <summary>
        /// Populates the default OpenIddict validation options and ensures
        /// that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The authentication scheme associated with the handler instance.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([CanBeNull] string name, [NotNull] OpenIddictValidationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (options.JsonWebTokenHandler == null)
            {
                throw new InvalidOperationException("The security token handler cannot be null.");
            }

            if (options.Issuer != null || options.MetadataAddress != null)
            {
                if (options.MetadataAddress == null)
                {
                    options.MetadataAddress = new Uri(".well-known/openid-configuration", UriKind.Relative);
                }

                if (!options.MetadataAddress.IsAbsoluteUri)
                {
                    if (options.Issuer == null || !options.Issuer.IsAbsoluteUri)
                    {
                        throw new InvalidOperationException("The authority must be provided and must be an absolute URL.");
                    }

                    if (!string.IsNullOrEmpty(options.Issuer.Fragment) || !string.IsNullOrEmpty(options.Issuer.Query))
                    {
                        throw new InvalidOperationException("The authority cannot contain a fragment or a query string.");
                    }

                    if (!options.Issuer.OriginalString.EndsWith("/"))
                    {
                        options.Issuer = new Uri(options.Issuer.OriginalString + "/", UriKind.Absolute);
                    }

                    options.MetadataAddress = new Uri(options.Issuer, options.MetadataAddress);
                }
            }

            foreach (var key in options.EncryptionCredentials.Select(credentials => credentials.Key))
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
