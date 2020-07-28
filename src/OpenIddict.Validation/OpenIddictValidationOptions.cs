/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict validation handler.
    /// </summary>
    public class OpenIddictValidationOptions
    {
        /// <summary>
        /// Gets the list of encryption credentials used by the OpenIddict validation services.
        /// Note: the encryption credentials are not used to protect/unprotect tokens issued
        /// by ASP.NET Core Data Protection, that uses its own key ring, configured separately.
        /// </summary>
        /// <remarks>
        /// Note: OpenIddict automatically sorts the credentials based on the following algorithm:
        /// <list type="bullet">
        ///   <item><description>Symmetric keys are always preferred when they can be used for the operation (e.g token encryption).</description></item>
        ///   <item><description>X.509 keys are always preferred to non-X.509 asymmetric keys.</description></item>
        ///   <item><description>X.509 keys with the furthest expiration date are preferred.</description></item>
        ///   <item><description>X.509 keys whose backing certificate is not yet valid are never preferred.</description></item>
        /// </list>
        /// </remarks>
        public List<EncryptingCredentials> EncryptionCredentials { get; } = new List<EncryptingCredentials>();

        /// <summary>
        /// Gets or sets the JWT handler used to protect and unprotect tokens.
        /// </summary>
        public JsonWebTokenHandler JsonWebTokenHandler { get; set; } = new JsonWebTokenHandler
        {
            SetDefaultTimesOnTokenCreation = false
        };

        /// <summary>
        /// Gets the list of the handlers responsible of processing the OpenIddict validation operations.
        /// Note: the list is automatically sorted based on the order assigned to each handler descriptor.
        /// As such, it MUST NOT be mutated after options initialization to preserve the exact order.
        /// </summary>
        public List<OpenIddictValidationHandlerDescriptor> Handlers { get; } =
            new List<OpenIddictValidationHandlerDescriptor>(OpenIddictValidationHandlers.DefaultHandlers);

        /// <summary>
        /// Gets or sets the type of validation used by the OpenIddict validation services.
        /// By default, local validation is always used.
        /// </summary>
        public OpenIddictValidationType ValidationType { get; set; } = OpenIddictValidationType.Direct;

        /// <summary>
        /// Gets or sets the client identifier sent to the authorization server when using remote validation.
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client secret sent to the authorization server when using remote validation.
        /// </summary>
        public string? ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a database call is made
        /// to validate the authorization entry associated with the received tokens.
        /// Note: enabling this option may have an impact on performance and
        /// can only be used with an OpenIddict-based authorization server.
        /// </summary>
        public bool EnableAuthorizationEntryValidation { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a database call is made
        /// to validate the token entry associated with the received tokens.
        /// Note: enabling this option may have an impact on performance but
        /// is required when the OpenIddict server emits reference tokens.
        /// </summary>
        public bool EnableTokenEntryValidation { get; set; }

        /// <summary>
        /// Gets or sets the absolute URL of the OAuth 2.0/OpenID Connect server.
        /// </summary>
        public Uri? Issuer { get; set; }

        /// <summary>
        /// Gets or sets the URL of the OAuth 2.0/OpenID Connect server discovery endpoint.
        /// When the URL is relative, <see cref="Issuer"/> must be set and absolute.
        /// </summary>
        public Uri? MetadataAddress { get; set; }

        /// <summary>
        /// Gets or sets the OAuth 2.0/OpenID Connect static server configuration, if applicable.
        /// </summary>
        public OpenIdConnectConfiguration? Configuration { get; set; }

        /// <summary>
        /// Gets or sets the configuration manager used to retrieve
        /// and cache the OAuth 2.0/OpenID Connect server configuration.
        /// </summary>
        public IConfigurationManager<OpenIdConnectConfiguration> ConfigurationManager { get; set; } = default!;

        /// <summary>
        /// Gets the intended audiences of this resource server.
        /// Setting this property is recommended when the authorization
        /// server issues access tokens for multiple distinct resource servers.
        /// </summary>
        public HashSet<string> Audiences { get; } = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the token validation parameters used by the OpenIddict validation services.
        /// </summary>
        public TokenValidationParameters TokenValidationParameters { get; } = new TokenValidationParameters
        {
            AuthenticationType = TokenValidationParameters.DefaultAuthenticationType,
            ClockSkew = TimeSpan.Zero,
            NameClaimType = Claims.Name,
            RoleClaimType = Claims.Role,
            // In previous versions of OpenIddict (1.x and 2.x), all the JWT tokens (access and identity tokens)
            // were issued with the generic "typ": "JWT" header. To prevent confused deputy and token substitution
            // attacks, a special "token_usage" claim was added to the JWT payload to convey the actual token type.
            // This validator overrides the default logic used by IdentityModel to resolve the type from this claim.
            TypeValidator = (type, token, parameters) =>
            {
                // If available, try to resolve the actual type from the "token_usage" claim.
                if (((JsonWebToken) token).TryGetPayloadValue(Claims.TokenUsage, out string usage))
                {
                    type = usage switch
                    {
                        TokenTypeHints.AccessToken => JsonWebTokenTypes.AccessToken,
                        TokenTypeHints.IdToken     => JsonWebTokenTypes.IdentityToken,

                        _ => throw new NotSupportedException(SR.GetResourceString(SR.ID1268))
                    };
                }

                // At this point, throw an exception if the type cannot be resolved from the "typ" header
                // (provided via the type delegate parameter) or inferred from the token_usage claim.
                if (string.IsNullOrEmpty(type))
                {
                    throw new SecurityTokenInvalidTypeException(SR.GetResourceString(SR.ID1269));
                }

                // Note: unlike IdentityModel, this custom validator deliberately uses case-insensitive comparisons.
                if (parameters.ValidTypes != null && parameters.ValidTypes.Any() &&
                   !parameters.ValidTypes.Contains(type, StringComparer.OrdinalIgnoreCase))
                {
                    throw new SecurityTokenInvalidTypeException(SR.GetResourceString(SR.ID1270))
                    {
                        InvalidType = type
                    };
                }

                return type;
            },
            // Note: audience and lifetime are manually validated by OpenIddict itself.
            ValidateAudience = false,
            ValidateLifetime = false
        };
    }
}
