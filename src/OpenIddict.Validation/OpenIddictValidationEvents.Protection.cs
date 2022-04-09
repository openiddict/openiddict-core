/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Validation;

public static partial class OpenIddictValidationEvents
{
    /// <summary>
    /// Represents an event called when validating a token.
    /// </summary>
    public class ValidateTokenContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateTokenContext"/> class.
        /// </summary>
        public ValidateTokenContext(OpenIddictValidationTransaction transaction)
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
        /// Gets or sets the token entry identifier associated with the token, if applicable.
        /// </summary>
        public string? TokenId { get; set; }

        /// <summary>
        /// Gets or sets the security principal resolved from the token.
        /// </summary>
        public ClaimsPrincipal? Principal { get; set; }

        /// <summary>
        /// Gets the token types that are considered valid. If no value is
        /// explicitly specified, all supported tokens are considered valid.
        /// </summary>
        public HashSet<string> ValidTokenTypes { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
