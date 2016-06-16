/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;

namespace OpenIddict {
    /// <summary>
    /// The default implementation of <see cref="OpenIddictToken{TKey}"/>
    /// which uses a string as a primary key.
    /// </summary>
    public class OpenIddictToken : OpenIddictToken<string> {
        public OpenIddictToken() {
            // Generate a new string identifier.
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents a token in the OpenIddict system.
    /// </summary>
    public class OpenIddictToken<TKey> where TKey : IEquatable<TKey> {
        /// <summary>
        /// Gets or sets the primary key for this token.
        /// </summary>
        public virtual TKey Id { get; set; }

        /// <summary>
        /// Gets or sets the token type for this token.
        /// </summary>
        public virtual string Type { get; set; }
    }
}
