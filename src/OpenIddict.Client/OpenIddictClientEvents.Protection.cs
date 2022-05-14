/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client;

public static partial class OpenIddictClientEvents
{
    /// <summary>
    /// Represents an event called when generating a token.
    /// </summary>
    public class GenerateTokenContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="GenerateTokenContext"/> class.
        /// </summary>
        public GenerateTokenContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if it is not available.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets a boolean indicating whether a token entry
        /// should be created to persist token metadata in a database.
        /// </summary>
        public bool CreateTokenEntry { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the token payload
        /// should be persisted alongside the token metadata in the database.
        /// </summary>
        public bool PersistTokenPayload { get; set; }

        /// <summary>
        /// Gets or sets the security principal used to create the token.
        /// </summary>
        public ClaimsPrincipal Principal { get; set; } = default!;

        /// <summary>
        /// Gets or sets the encryption credentials used to encrypt the token.
        /// </summary>
        public EncryptingCredentials? EncryptionCredentials { get; set; }

        /// <summary>
        /// Gets or sets the signing credentials used to sign the token.
        /// </summary>
        public SigningCredentials? SigningCredentials { get; set; }

        /// <summary>
        /// Gets or sets the security token handler used to serialize the security principal.
        /// </summary>
        public JsonWebTokenHandler SecurityTokenHandler { get; set; } = default!;

        /// <summary>
        /// Gets or sets the token returned to the client application.
        /// </summary>
        public string? Token { get; set; }

        /// <summary>
        /// Gets or sets the format of the token (e.g JWT or ASP.NET Core Data Protection) to create.
        /// </summary>
        public string TokenFormat { get; set; } = default!;

        /// <summary>
        /// Gets or sets the type of the token to create.
        /// </summary>
        public string TokenType { get; set; } = default!;
    }

    /// <summary>
    /// Represents an event called when validating a token.
    /// </summary>
    public class ValidateTokenContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateTokenContext"/> class.
        /// </summary>
        public ValidateTokenContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if it is not available.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets a boolean indicating whether lifetime validation is disabled.
        /// </summary>
        public bool DisableLifetimeValidation { get; set; }

        /// <summary>
        /// Gets or sets the security token handler used to validate the token.
        /// </summary>
        public JsonWebTokenHandler SecurityTokenHandler { get; set; } = default!;

        /// <summary>
        /// Gets or sets the validation parameters used to verify the authenticity of tokens.
        /// </summary>
        public TokenValidationParameters TokenValidationParameters { get; set; } = default!;

        /// <summary>
        /// Gets or sets the token to validate.
        /// </summary>
        public string Token { get; set; } = default!;

        /// <summary>
        /// Gets or sets the token type hint specified by the client, if applicable.
        /// </summary>
        public string? TokenTypeHint { get; set; } = default!;

        /// <summary>
        /// Gets or sets the token entry identifier associated with the token, if applicable.
        /// </summary>
        public string? TokenId { get; set; }

        /// <summary>
        /// Gets or sets the security principal resolved from the token.
        /// </summary>
        public ClaimsPrincipal? Principal { get; set; }

        /// <summary>
        /// Gets the token types that are considered valid.
        /// </summary>
        public HashSet<string> ValidTokenTypes { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
