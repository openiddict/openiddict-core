/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;

namespace OpenIddict {
    /// <summary>
    /// The default implementation of <see cref="OpenIddictScope{TKey}"/>
    /// which uses a string as a primary key.
    /// </summary>
    public class OpenIddictScope : OpenIddictScope<string> {
        public OpenIddictScope() {
            // Generate a new string identifier.
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents a scope in the OpenIddict system.
    /// </summary>
    public class OpenIddictScope<TKey> where TKey : IEquatable<TKey> {
        /// <summary>
        /// Gets or sets the primary key for this scope.
        /// </summary>
        public virtual TKey Id { get; set; }

        /// <summary>
        /// Gets or sets the public description for this scope.
        /// </summary>
        public virtual string Description { get; set; }
    }
}
