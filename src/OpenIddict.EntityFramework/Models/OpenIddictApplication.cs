/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;

namespace OpenIddict {
    /// <summary>
    /// The default implementation of <see cref="OpenIddictApplication{TKey}"/>
    /// which uses a string as a primary key.
    /// </summary>
    public class OpenIddictApplication : OpenIddictApplication<string, OpenIddictToken> {
        public OpenIddictApplication() {
            // Generate a new string identifier.
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// The default implementation of <see cref="OpenIddictApplication{TKey}"/>.
    /// </summary>
    public class OpenIddictApplication<TKey> : OpenIddictApplication<TKey, OpenIddictToken<TKey>>
        where TKey : IEquatable<TKey> { }

    /// <summary>
    /// Represents an application in the OpenIddict system.
    /// </summary>
    public class OpenIddictApplication<TKey, TToken> where TKey : IEquatable<TKey> {
        /// <summary>
        /// Gets or sets the primary key for this application.
        /// </summary>
        public virtual TKey Id { get; set; }

        /// <summary>
        /// Gets or sets the friendly name used in a UI for this application.
        /// </summary>
        public virtual string DisplayName { get; set; }

        /// <summary>
        /// Gets or sets the client identifier for this application.
        /// </summary>
        public virtual string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client secret for this application.
        /// </summary>
        /// <remarks>Use hash of the secret for security purposes.</remarks>
        public virtual string ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the callback URL for this application.
        /// </summary>
        public virtual string RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the logout callback URL for this application.
        /// </summary>
        public virtual string LogoutRedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the application type for this application.
        /// <para>Can be:</para>
        /// <para><see cref="P:OpenIddict.OpenIddictConstants.ApplicationTypes.Public"/></para>
        /// <para><see cref="P:OpenIddict.OpenIddictConstants.ApplicationTypes.Confidential"/></para>
        /// </summary>
        public virtual string Type { get; set; } = OpenIddictConstants.ClientTypes.Public;

        /// <summary>
        /// Navigation property for the tokens associated with this application.
        /// </summary>
        public virtual IList<TToken> Tokens { get; } = new List<TToken>();
    }
}