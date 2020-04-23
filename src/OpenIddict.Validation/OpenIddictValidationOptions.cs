/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict validation handler.
    /// </summary>
    public class OpenIddictValidationOptions
    {
        /// <summary>
        /// Gets the list of credentials used to encrypt the tokens issued by the
        /// OpenIddict validation services. Note: only symmetric credentials are supported.
        /// </summary>
        public IList<EncryptingCredentials> EncryptionCredentials { get; } = new List<EncryptingCredentials>();

        /// <summary>
        /// Gets or sets the JWT handler used to protect and unprotect tokens.
        /// </summary>
        public JsonWebTokenHandler JsonWebTokenHandler { get; set; } = new JsonWebTokenHandler
        {
            SetDefaultTimesOnTokenCreation = false
        };

        /// <summary>
        /// Gets the list of the user-defined/custom handlers responsible of processing the OpenIddict validation requests.
        /// Note: the handlers added to this list must be also registered in the DI container using an appropriate lifetime.
        /// </summary>
        public IList<OpenIddictValidationHandlerDescriptor> CustomHandlers { get; } =
            new List<OpenIddictValidationHandlerDescriptor>();

        /// <summary>
        /// Gets the list of the built-in handlers responsible of processing the OpenIddict validation requests
        /// </summary>
        public IList<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } =
            new List<OpenIddictValidationHandlerDescriptor>(OpenIddictValidationHandlers.DefaultHandlers);

        /// <summary>
        /// Gets or sets a boolean indicating whether a database call is made
        /// to validate the authorization entry associated with the received tokens.
        /// Note: enabling this option may have an impact on performance and
        /// can only be used with an OpenIddict-based authorization server.
        /// </summary>
        public bool EnableAuthorizationValidation { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a database call is made
        /// to validate the token entry associated with the received tokens.
        /// Note: enabling this option may have an impact on performance but
        /// is required when the OpenIddict server emits reference tokens.
        /// </summary>
        public bool EnableTokenValidation { get; set; }

        /// <summary>
        /// Gets or sets the absolute URL of the OAuth 2.0/OpenID Connect server.
        /// </summary>
        public Uri Issuer { get; set; }

        /// <summary>
        /// Gets or sets the URL of the OAuth 2.0/OpenID Connect server discovery endpoint.
        /// When the URL is relative, <see cref="Issuer"/> must be set and absolute.
        /// </summary>
        public Uri MetadataAddress { get; set; }

        /// <summary>
        /// Gets the intended audiences of this resource server.
        /// Setting this property is recommended when the authorization
        /// server issues access tokens for multiple distinct resource servers.
        /// </summary>
        public ISet<string> Audiences { get; } = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the optional "realm" value returned to
        /// the caller as part of the WWW-Authenticate header.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Gets the token validation parameters used by the OpenIddict validation services.
        /// </summary>
        public TokenValidationParameters TokenValidationParameters { get; } = new TokenValidationParameters
        {
            ClockSkew = TimeSpan.Zero,
            NameClaimType = Claims.Name,
            RoleClaimType = Claims.Role,
            // Note: audience and lifetime are manually validated by OpenIddict itself.
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidTypes = new[] { JsonWebTokenTypes.AccessToken }
        };
    }
}
