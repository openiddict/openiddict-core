/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using JetBrains.Annotations;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace OpenIddict.Server
{
    public static partial class OpenIddictServerEvents
    {
        /// <summary>
        /// Represents an event called for each request to the configuration endpoint to give the user code
        /// a chance to manually extract the configuration request from the ambient HTTP context.
        /// </summary>
        public class ExtractConfigurationRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ExtractConfigurationRequestContext"/> class.
            /// </summary>
            public ExtractConfigurationRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called for each request to the configuration endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public class ValidateConfigurationRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ValidateConfigurationRequestContext"/> class.
            /// </summary>
            public ValidateConfigurationRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called for each validated configuration request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public class HandleConfigurationRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="HandleConfigurationRequestContext"/> class.
            /// </summary>
            public HandleConfigurationRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets the additional parameters returned to the client application.
            /// </summary>
            public IDictionary<string, OpenIddictParameter> Metadata { get; } =
                new Dictionary<string, OpenIddictParameter>(StringComparer.Ordinal);

            /// <summary>
            /// Gets or sets the authorization endpoint address.
            /// </summary>
            public Uri AuthorizationEndpoint { get; set; }

            /// <summary>
            /// Gets or sets the JWKS endpoint address.
            /// </summary>
            public Uri CryptographyEndpoint { get; set; }

            /// <summary>
            /// Gets or sets the device endpoint address.
            /// </summary>
            public Uri DeviceEndpoint { get; set; }

            /// <summary>
            /// Gets or sets the introspection endpoint address.
            /// </summary>
            public Uri IntrospectionEndpoint { get; set; }

            /// <summary>
            /// Gets or sets the logout endpoint address.
            /// </summary>
            public Uri LogoutEndpoint { get; set; }

            /// <summary>
            /// Gets or sets the revocation endpoint address.
            /// </summary>
            public Uri RevocationEndpoint { get; set; }

            /// <summary>
            /// Gets or sets the token endpoint address.
            /// </summary>
            public Uri TokenEndpoint { get; set; }

            /// <summary>
            /// Gets or sets the userinfo endpoint address.
            /// </summary>
            public Uri UserinfoEndpoint { get; set; }

            /// <summary>
            /// Gets the list of claims supported by the authorization server.
            /// </summary>
            public HashSet<string> Claims { get; } = new HashSet<string>(StringComparer.Ordinal);

            /// <summary>
            /// Gets a list of the code challenge methods
            /// supported by the authorization server.
            /// </summary>
            public HashSet<string> CodeChallengeMethods { get; } = new HashSet<string>(StringComparer.Ordinal);

            /// <summary>
            /// Gets the list of grant types
            /// supported by the authorization server.
            /// </summary>
            public HashSet<string> GrantTypes { get; } = new HashSet<string>(StringComparer.Ordinal);

            /// <summary>
            /// Gets a list of signing algorithms supported by the
            /// authorization server for signing the identity tokens.
            /// </summary>
            public HashSet<string> IdTokenSigningAlgorithms { get; } = new HashSet<string>(StringComparer.Ordinal);

            /// <summary>
            /// Gets a list of client authentication methods supported by
            /// the introspection endpoint provided by the authorization server.
            /// </summary>
            public HashSet<string> IntrospectionEndpointAuthenticationMethods { get; } = new HashSet<string>(StringComparer.Ordinal);

            /// <summary>
            /// Gets the list of response modes
            /// supported by the authorization server.
            /// </summary>
            public HashSet<string> ResponseModes { get; } = new HashSet<string>(StringComparer.Ordinal);

            /// <summary>
            /// Gets the list of response types
            /// supported by the authorization server.
            /// </summary>
            public HashSet<string> ResponseTypes { get; } = new HashSet<string>(StringComparer.Ordinal);

            /// <summary>
            /// Gets a list of client authentication methods supported by
            /// the revocation endpoint provided by the authorization server.
            /// </summary>
            public HashSet<string> RevocationEndpointAuthenticationMethods { get; } = new HashSet<string>(StringComparer.Ordinal);

            /// <summary>
            /// Gets the list of scope values
            /// supported by the authorization server.
            /// </summary>
            public HashSet<string> Scopes { get; } = new HashSet<string>(StringComparer.Ordinal);

            /// <summary>
            /// Gets the list of subject types
            /// supported by the authorization server.
            /// </summary>
            public HashSet<string> SubjectTypes { get; } = new HashSet<string>(StringComparer.Ordinal);

            /// <summary>
            /// Gets a list of client authentication methods supported by
            /// the token endpoint provided by the authorization server.
            /// </summary>
            public HashSet<string> TokenEndpointAuthenticationMethods { get; } = new HashSet<string>(StringComparer.Ordinal);
        }

        /// <summary>
        /// Represents an event called before the configuration response is returned to the caller.
        /// </summary>
        public class ApplyConfigurationResponseContext : BaseRequestContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ApplyConfigurationResponseContext"/> class.
            /// </summary>
            public ApplyConfigurationResponseContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets the error code returned to the client application.
            /// When the response indicates a successful response,
            /// this property returns <c>null</c>.
            /// </summary>
            public string Error => Response.Error;
        }

        /// <summary>
        /// Represents an event called for each request to the cryptography endpoint to give the user code
        /// a chance to manually extract the cryptography request from the ambient HTTP context.
        /// </summary>
        public class ExtractCryptographyRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ExtractCryptographyRequestContext"/> class.
            /// </summary>
            public ExtractCryptographyRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called for each request to the cryptography endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public class ValidateCryptographyRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ValidateCryptographyRequestContext"/> class.
            /// </summary>
            public ValidateCryptographyRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called for each validated cryptography request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public class HandleCryptographyRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="HandleCryptographyRequestContext"/> class.
            /// </summary>
            public HandleCryptographyRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets the list of JSON Web Keys exposed by the JWKS endpoint.
            /// </summary>
            public List<JsonWebKey> Keys { get; } = new List<JsonWebKey>();
        }

        /// <summary>
        /// Represents an event called before the cryptography response is returned to the caller.
        /// </summary>
        public class ApplyCryptographyResponseContext : BaseRequestContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ApplyCryptographyResponseContext"/> class.
            /// </summary>
            public ApplyCryptographyResponseContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets the error code returned to the client application.
            /// When the response indicates a successful response,
            /// this property returns <c>null</c>.
            /// </summary>
            public string Error => Response.Error;
        }
    }
}
