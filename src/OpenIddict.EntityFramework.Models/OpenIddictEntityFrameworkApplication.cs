/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace OpenIddict.EntityFramework.Models
{
    /// <summary>
    /// Represents an OpenIddict application.
    /// </summary>
    public class OpenIddictEntityFrameworkApplication : OpenIddictEntityFrameworkApplication<string, OpenIddictEntityFrameworkAuthorization, OpenIddictEntityFrameworkToken>
    {
        public OpenIddictEntityFrameworkApplication()
        {
            // Generate a new string identifier.
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents an OpenIddict application.
    /// </summary>
    [DebuggerDisplay("Id = {Id.ToString(),nq} ; ClientId = {ClientId,nq} ; Type = {Type,nq}")]
    public class OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TToken>
        where TKey : notnull, IEquatable<TKey>
        where TAuthorization : class
        where TToken : class
    {
        /// <summary>
        /// Gets the list of the authorizations associated with this application.
        /// </summary>
        public virtual ICollection<TAuthorization> Authorizations { get; } = new HashSet<TAuthorization>();

        /// <summary>
        /// Gets or sets the client identifier associated with the current application.
        /// </summary>
        public virtual string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client secret associated with the current application.
        /// Note: depending on the application manager used to create this instance,
        /// this property may be hashed or encrypted for security reasons.
        /// </summary>
        public virtual string? ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the concurrency token.
        /// </summary>
        public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Gets or sets the consent type associated with the current application.
        /// </summary>
        public virtual string? ConsentType { get; set; }

        /// <summary>
        /// Gets or sets the display name associated with the current application.
        /// </summary>
        public virtual string? DisplayName { get; set; }

        /// <summary>
        /// Gets or sets the localized display names
        /// associated with the current application,
        /// serialized as a JSON object.
        /// </summary>
        public virtual string? DisplayNames { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier associated with the current application.
        /// </summary>
        [AllowNull, MaybeNull]
        public virtual TKey Id { get; set; } = default!;

        /// <summary>
        /// Gets or sets the permissions associated with the
        /// current application, serialized as a JSON array.
        /// </summary>
        public virtual string? Permissions { get; set; }

        /// <summary>
        /// Gets or sets the logout callback URLs associated with
        /// the current application, serialized as a JSON array.
        /// </summary>
        public virtual string? PostLogoutRedirectUris { get; set; }

        /// <summary>
        /// Gets or sets the additional properties serialized as a JSON object,
        /// or <c>null</c> if no bag was associated with the current application.
        /// </summary>
        public virtual string? Properties { get; set; }

        /// <summary>
        /// Gets or sets the callback URLs associated with the
        /// current application, serialized as a JSON array.
        /// </summary>
        public virtual string? RedirectUris { get; set; }

        /// <summary>
        /// Gets or sets the requirements associated with the
        /// current application, serialized as a JSON array.
        /// </summary>
        public virtual string? Requirements { get; set; }

        /// <summary>
        /// Gets the list of the tokens associated with this application.
        /// </summary>
        public virtual ICollection<TToken> Tokens { get; } = new HashSet<TToken>();

        /// <summary>
        /// Gets or sets the application type associated with the current application.
        /// </summary>
        public virtual string? Type { get; set; }
    }
}