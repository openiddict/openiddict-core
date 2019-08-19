/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using JetBrains.Annotations;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Server
{
    public static partial class OpenIddictServerEvents
    {
        /// <summary>
        /// Represents an abstract base class used for certain event contexts.
        /// </summary>
        public abstract class BaseSerializingContext : BaseContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="BaseSerializingContext"/> class.
            /// </summary>
            public BaseSerializingContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets or sets the security principal containing the claims to serialize.
            /// </summary>
            public ClaimsPrincipal Principal { get; set; }

            /// <summary>
            /// Gets or sets the encrypting credentials used to encrypt the token.
            /// </summary>
            public EncryptingCredentials EncryptingCredentials { get; set; }

            /// <summary>
            /// Gets or sets the signing credentials used to sign the token.
            /// </summary>
            public SigningCredentials SigningCredentials { get; set; }

            /// <summary>
            /// Gets or sets the security token handler used to serialize the token.
            /// </summary>
            public JsonWebTokenHandler SecurityTokenHandler { get; set; }

            /// <summary>
            /// Gets or sets the issuer address.
            /// </summary>
            public Uri Issuer { get; set; }

            /// <summary>
            /// Gets or sets the token returned to the client application.
            /// </summary>
            public string Token { get; set; }

            /// <summary>
            /// Gets or sets the token usage.
            /// </summary>
            public string TokenUsage { get; set; }

            /// <summary>
            /// Gets a boolean indicating whether the
            /// <see cref="HandleSerialization()"/> method was called.
            /// </summary>
            public bool IsHandled { get; private set; }

            /// <summary>
            /// Marks the serialization process as handled by the application code.
            /// </summary>
            public void HandleSerialization() => IsHandled = true;
        }

        /// <summary>
        /// Represents an abstract base class used for certain event contexts.
        /// </summary>
        public abstract class BaseDeserializingContext : BaseContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="BaseDeserializingContext"/> class.
            /// </summary>
            public BaseDeserializingContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets or sets the security principal containing the deserialized claims.
            /// </summary>
            public ClaimsPrincipal Principal { get; set; }

            /// <summary>
            /// Gets or sets the validation parameters used to verify the authenticity of access tokens.
            /// Note: this property is only used when <see cref="SecurityTokenHandler"/> is not <c>null</c>.
            /// </summary>
            public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();

            /// <summary>
            /// Gets or sets the security token handler used to
            /// deserialize the authentication ticket.
            /// </summary>
            public JsonWebTokenHandler SecurityTokenHandler { get; set; }

            /// <summary>
            /// Gets or sets the token used by the client application.
            /// </summary>
            public string Token { get; set; }

            /// <summary>
            /// Gets or sets the token usage.
            /// </summary>
            public string TokenUsage { get; set; }

            /// <summary>
            /// Gets a boolean indicating whether the
            /// <see cref="HandleDeserialization()"/> method was called.
            /// </summary>
            public bool IsHandled { get; private set; }

            /// <summary>
            /// Marks the deserialization process as handled by the application code.
            /// </summary>
            public void HandleDeserialization() => IsHandled = true;
        }

        /// <summary>
        /// Represents an event called when serializing an access token.
        /// </summary>
        public class SerializeAccessTokenContext : BaseSerializingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="SerializeAccessTokenContext"/> class.
            /// </summary>
            public SerializeAccessTokenContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
                => TokenUsage = TokenUsages.AccessToken;
        }

        /// <summary>
        /// Represents an event called when serializing an authorization code.
        /// </summary>
        public class SerializeAuthorizationCodeContext : BaseSerializingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="SerializeAuthorizationCodeContext"/> class.
            /// </summary>
            public SerializeAuthorizationCodeContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
                => TokenUsage = TokenUsages.AuthorizationCode;
        }

        /// <summary>
        /// Represents an event called when serializing an identity token.
        /// </summary>
        public class SerializeIdentityTokenContext : BaseSerializingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="SerializeIdentityTokenContext"/> class.
            /// </summary>
            public SerializeIdentityTokenContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
                => TokenUsage = TokenUsages.IdToken;
        }

        /// <summary>
        /// Represents an event called when serializing a refresh token.
        /// </summary>
        public class SerializeRefreshTokenContext : BaseSerializingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="SerializeRefreshTokenContext"/> class.
            /// </summary>
            public SerializeRefreshTokenContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
                => TokenUsage = TokenUsages.RefreshToken;
        }

        /// <summary>
        /// Represents an event called when deserializing an access token.
        /// </summary>
        public class DeserializeAccessTokenContext : BaseDeserializingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="DeserializeAccessTokenContext"/> class.
            /// </summary>
            public DeserializeAccessTokenContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
                => TokenUsage = TokenUsages.AccessToken;
        }

        /// <summary>
        /// Represents an event called when deserializing an authorization code.
        /// </summary>
        public class DeserializeAuthorizationCodeContext : BaseDeserializingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="DeserializeAuthorizationCodeContext"/> class.
            /// </summary>
            public DeserializeAuthorizationCodeContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
                => TokenUsage = TokenUsages.AuthorizationCode;
        }

        /// <summary>
        /// Represents an event called when deserializing an identity token.
        /// </summary>
        public class DeserializeIdentityTokenContext : BaseDeserializingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="DeserializeIdentityTokenContext"/> class.
            /// </summary>
            public DeserializeIdentityTokenContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
                => TokenUsage = TokenUsages.IdToken;
        }

        /// <summary>
        /// Represents an event called when deserializing a refresh token.
        /// </summary>
        public class DeserializeRefreshTokenContext : BaseDeserializingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="DeserializeRefreshTokenContext"/> class.
            /// </summary>
            public DeserializeRefreshTokenContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
                => TokenUsage = TokenUsages.RefreshToken;
        }
    }
}
