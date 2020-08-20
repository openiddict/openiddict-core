/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace OpenIddict.EntityFrameworkCore.Models
{
    /// <summary>
    /// Represents an OpenIddict token.
    /// </summary>
    public class OpenIddictEntityFrameworkCoreToken : OpenIddictEntityFrameworkCoreToken<string, OpenIddictEntityFrameworkCoreApplication, OpenIddictEntityFrameworkCoreAuthorization>
    {
        public OpenIddictEntityFrameworkCoreToken()
        {
            // Generate a new string identifier.
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents an OpenIddict token.
    /// </summary>
    public class OpenIddictEntityFrameworkCoreToken<TKey> : OpenIddictEntityFrameworkCoreToken<TKey, OpenIddictEntityFrameworkCoreApplication<TKey>, OpenIddictEntityFrameworkCoreAuthorization<TKey>>
        where TKey : IEquatable<TKey>
    {
    }

    /// <summary>
    /// Represents an OpenIddict token.
    /// </summary>
    [DebuggerDisplay("Id = {Id.ToString(),nq} ; Subject = {Subject,nq} ; Type = {Type,nq} ; Status = {Status,nq}")]
    public class OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
        where TKey : IEquatable<TKey>
        where TApplication : class
        where TAuthorization : class
    {
        /// <summary>
        /// Gets or sets the application associated with the current token.
        /// </summary>
        public virtual TApplication? Application { get; set; }

        /// <summary>
        /// Gets or sets the authorization associated with the current token.
        /// </summary>
        public virtual TAuthorization? Authorization { get; set; }

        /// <summary>
        /// Gets or sets the concurrency token.
        /// </summary>
        public virtual string? ConcurrencyToken { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Gets or sets the creation date of the current token.
        /// </summary>
        public virtual DateTimeOffset? CreationDate { get; set; }

        /// <summary>
        /// Gets or sets the expiration date of the current token.
        /// </summary>
        public virtual DateTimeOffset? ExpirationDate { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier associated with the current token.
        /// </summary>
        [AllowNull, MaybeNull]
        public virtual TKey Id { get; set; } = default!;

        /// <summary>
        /// Gets or sets the payload of the current token, if applicable.
        /// Note: this property is only used for reference tokens
        /// and may be encrypted for security reasons.
        /// </summary>
        public virtual string? Payload { get; set; }

        /// <summary>
        /// Gets or sets the additional properties serialized as a JSON object,
        /// or <c>null</c> if no bag was associated with the current token.
        /// </summary>
        public virtual string? Properties { get; set; }

        /// <summary>
        /// Gets or sets the reference identifier associated
        /// with the current token, if applicable.
        /// Note: this property is only used for reference tokens
        /// and may be hashed or encrypted for security reasons.
        /// </summary>
        public virtual string? ReferenceId { get; set; }

        /// <summary>
        /// Gets or sets the status of the current token.
        /// </summary>
        public virtual string? Status { get; set; }

        /// <summary>
        /// Gets or sets the subject associated with the current token.
        /// </summary>
        public virtual string? Subject { get; set; }

        /// <summary>
        /// Gets or sets the type of the current token.
        /// </summary>
        public virtual string? Type { get; set; }
    }
}
