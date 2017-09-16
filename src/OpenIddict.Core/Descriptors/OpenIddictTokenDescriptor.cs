using System;

namespace OpenIddict.Core
{
    /// <summary>
    /// Represents an OpenIddict token descriptor.
    /// </summary>
    public class OpenIddictTokenDescriptor
    {
        /// <summary>
        /// Gets or sets the application identifier associated with the token.
        /// </summary>
        public string ApplicationId { get; set; }

        /// <summary>
        /// Gets or sets the authorization identifier associated with the token.
        /// </summary>
        public string AuthorizationId { get; set; }

        /// <summary>
        /// Gets or sets the encrypted payload associated with the token.
        /// </summary>
        public string Ciphertext { get; set; }

        /// <summary>
        /// Gets or sets the creation date associated with the token.
        /// </summary>
        public DateTimeOffset? CreationDate { get; set; }

        /// <summary>
        /// Gets or sets the expiration date associated with the token.
        /// </summary>
        public DateTimeOffset? ExpirationDate { get; set; }

        /// <summary>
        /// Gets or sets the cryptographic hash associated with the token.
        /// </summary>
        public string Hash { get; set; }

        /// <summary>
        /// Gets or sets the subject associated with the token.
        /// </summary>
        public string Subject { get; set; }

        /// <summary>
        /// Gets or sets the token type.
        /// </summary>
        public string Type { get; set; }
    }
}
