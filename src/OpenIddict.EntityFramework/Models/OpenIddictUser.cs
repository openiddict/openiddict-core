/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace OpenIddict {
    /// <summary>
    /// Represents an OpenIddict user.
    /// </summary>
    public class OpenIddictUser : OpenIddictUser<OpenIddictAuthorization, OpenIddictToken> { }

    /// <summary>
    /// Represents an OpenIddict user.
    /// </summary>
    public class OpenIddictUser<TAuthorization, TToken> : OpenIddictUser<TAuthorization, TToken, string> {
        public OpenIddictUser() {
            // Generate a new string identifier.
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents an OpenIddict user.
    /// </summary>
    public class OpenIddictUser<TAuthorization, TToken, TKey> : IdentityUser<TKey> where TKey : IEquatable<TKey> {
        /// <summary>
        /// Gets the list of the authorizations associated with this user profile.
        /// </summary>
        public virtual IList<TAuthorization> Authorizations { get; } = new List<TAuthorization>();

        /// <summary>
        /// Gets the list of the tokens associated with this user profile.
        /// </summary>
        public virtual IList<TToken> Tokens { get; } = new List<TToken>();
    }
}
