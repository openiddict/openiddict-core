using System;
using System.Security.Claims;

namespace OpenIddict.Abstractions
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
        /// Gets or sets the creation date associated with the token.
        /// </summary>
        public DateTimeOffset? CreationDate { get; set; }

        /// <summary>
        /// Gets or sets the expiration date associated with the token.
        /// </summary>
        public DateTimeOffset? ExpirationDate { get; set; }

        /// <summary>
        /// Gets or sets the payload associated with the token.
        /// </summary>
        public string Payload { get; set; }

        /// <summary>
        /// Gets or sets the optional principal associated with the token.
        /// Note: this property is not stored by the default token stores.
        /// </summary>
        public ClaimsPrincipal Principal { get; set; }

        /// <summary>
        /// Gets or sets the reference identifier associated with the token.
        /// Note: depending on the application manager used when creating it,
        /// this property may be hashed or encrypted for security reasons.
        /// </summary>
        public string ReferenceId { get; set; }

        /// <summary>
        /// Gets or sets the status associated with the token.
        /// </summary>
        public string Status { get; set; }

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
