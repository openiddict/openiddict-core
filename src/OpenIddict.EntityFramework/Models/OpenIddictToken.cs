/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;

namespace OpenIddict {
    /// <summary>
    /// Represents an OpenIddict token.
    /// </summary>
    public class OpenIddictToken : OpenIddictToken<string> {
        public OpenIddictToken() {
            // Generate a new string identifier.
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents an OpenIddict token.
    /// </summary>
    public class OpenIddictToken<TKey> where TKey : IEquatable<TKey> {
        /// <summary>
        /// Gets or sets the identifier of the authorization attached with the current token.
        /// This property may be null if the token was issued without
        /// requiring the user consent or is bound to a client application.
        /// </summary>
        public virtual TKey AuthorizationId { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier
        /// associated with the current token.
        /// </summary>
        public virtual TKey Id { get; set; }

        /// <summary>
        /// Gets or sets the type of the current token.
        /// </summary>
        public virtual string Type { get; set; }

        /// <summary>
        /// Gets or sets the identifier of the user attached with the current token.
        /// This property is null if the token represents a client application.
        /// </summary>
        public virtual TKey UserId { get; set; }
    }
}
