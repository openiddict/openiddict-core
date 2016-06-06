/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;

namespace OpenIddict {
    /// <summary>
    /// Represents an OpenIddict application.
    /// </summary>
    public class OpenIddictApplication : OpenIddictApplication<string> {
        public OpenIddictApplication() {
            // Generate a new string identifier.
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents an OpenIddict application.
    /// </summary>
    public class OpenIddictApplication<TKey> where TKey : IEquatable<TKey> {
        /// <summary>
        /// Gets or sets the display name
        /// associated with the current application.
        /// </summary>
        public virtual string DisplayName { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier
        /// associated with the current application.
        /// </summary>
        public virtual TKey Id { get; set; }

        /// <summary>
        /// Gets or sets the logout callback URL
        /// associated with the current application.
        /// </summary>
        public virtual string LogoutRedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the callback URL
        /// associated with the current application.
        /// </summary>
        public virtual string RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the hashed secret
        /// associated with the current application.
        /// </summary>
        public virtual string Secret { get; set; }

        /// <summary>
        /// Gets or sets the application type
        /// associated with the current application.
        /// </summary>
        public virtual string Type { get; set; } = OpenIddictConstants.ClientTypes.Public;
    }
}