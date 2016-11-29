/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;

namespace OpenIddict.Models {
    /// <summary>
    /// Represents an OpenIddict application.
    /// </summary>
    public class OpenIddictApplication : OpenIddictApplication<string, OpenIddictToken> {
        public OpenIddictApplication() {
            // Generate a new string identifier.
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents an OpenIddict application.
    /// </summary>
    public class OpenIddictApplication<TKey> : OpenIddictApplication<TKey, OpenIddictToken<TKey>>
        where TKey : IEquatable<TKey> { }

    /// <summary>
    /// Represents an OpenIddict application.
    /// </summary>
    public class OpenIddictApplication<TKey, TToken> where TKey : IEquatable<TKey> {
        /// <summary>
        /// Gets or sets the client identifier
        /// associated with the current application.
        /// </summary>
        public virtual string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the hashed client secret
        /// associated with the current application.
        /// </summary>
        public virtual string ClientSecret { get; set; }

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
        /// Gets the list of the tokens associated with this application.
        /// </summary>
        public virtual IList<TToken> Tokens { get; } = new List<TToken>();

        /// <summary>
        /// Gets or sets the application type
        /// associated with the current application.
        /// </summary>
        public virtual string Type { get; set; } = "public";
    }
}