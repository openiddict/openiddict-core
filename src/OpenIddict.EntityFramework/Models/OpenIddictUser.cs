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
    /// The default implementation of <see cref="OpenIddictUser{TKey}"/>
    /// which uses a string as a primary key.
    /// </summary>
    public class OpenIddictUser : OpenIddictUser<string, OpenIddictAuthorization, OpenIddictToken> {
        public OpenIddictUser() {
            // Generate a new string identifier.
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// The default implementation of <see cref="OpenIddictUser{TKey, TAuthorization, TToken}"/>.
    /// </summary>
    public class OpenIddictUser<TKey> : OpenIddictUser<TKey, OpenIddictAuthorization<TKey>, OpenIddictToken<TKey>>
        where TKey : IEquatable<TKey> { }

    /// <summary>
    /// Represents a user in the OpenIddict system.
    /// </summary>
    public class OpenIddictUser<TKey, TAuthorization, TToken> : IdentityUser<TKey> where TKey : IEquatable<TKey> {
        /// <summary>
        /// Navigation property for the authorizations associated with this user profile.
        /// </summary>
        public virtual IList<TAuthorization> Authorizations { get; } = new List<TAuthorization>();

        /// <summary>
        /// Navigation property for the tokens associated with this user profile.
        /// </summary>
        public virtual IList<TToken> Tokens { get; } = new List<TToken>();
    }
}
