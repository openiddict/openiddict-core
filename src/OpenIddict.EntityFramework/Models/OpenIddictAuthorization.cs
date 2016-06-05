/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;

namespace OpenIddict {
    /// <summary>
    /// Represents an OpenIddict authorization.
    /// </summary>
    public class OpenIddictAuthorization : OpenIddictAuthorization<string, OpenIddictToken> {
        public OpenIddictAuthorization() {
            // Generate a new string identifier.
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents an OpenIddict authorization.
    /// </summary>
    public class OpenIddictAuthorization<TKey> : OpenIddictAuthorization<TKey, OpenIddictToken<TKey>>
        where TKey : IEquatable<TKey> { }

    /// <summary>
    /// Represents an OpenIddict authorization.
    /// </summary>
    public class OpenIddictAuthorization<TKey, TToken> where TKey : IEquatable<TKey> {
        /// <summary>
        /// Gets or sets the unique identifier
        /// associated with the current authorization.
        /// </summary>
        public virtual TKey Id { get; set; }

        /// <summary>
        /// Gets or sets the space-delimited scopes
        /// associated with the current authorization.
        /// </summary>
        public virtual string Scope { get; set; }

        /// <summary>
        /// Gets or sets the list of tokens
        /// associated with the current authorization.
        /// </summary>
        public virtual IList<TToken> Tokens { get; } = new List<TToken>();
    }
}
