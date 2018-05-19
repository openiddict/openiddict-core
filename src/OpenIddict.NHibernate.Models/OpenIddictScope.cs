/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;

namespace OpenIddict.NHibernate.Models
{
    /// <summary>
    /// Represents an OpenIddict scope.
    /// </summary>
    public class OpenIddictScope : OpenIddictScope<string>
    {
        public OpenIddictScope()
        {
            // Generate a new string identifier.
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents an OpenIddict scope.
    /// </summary>
    [DebuggerDisplay("Id = {Id.ToString(),nq} ; Name = {Name,nq}")]
    public class OpenIddictScope<TKey> where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Gets or sets the public description
        /// associated with the current scope.
        /// </summary>
        public virtual string Description { get; set; }

        /// <summary>
        /// Gets or sets the display name
        /// associated with the current scope.
        /// </summary>
        public virtual string DisplayName { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier
        /// associated with the current scope.
        /// </summary>
        public virtual TKey Id { get; set; }

        /// <summary>
        /// Gets or sets the unique name
        /// associated with the current scope.
        /// </summary>
        public virtual string Name { get; set; }

        /// <summary>
        /// Gets or sets the additional properties serialized as a JSON object,
        /// or <c>null</c> if no bag was associated with the current scope.
        /// </summary>
        public virtual string Properties { get; set; }

        /// <summary>
        /// Gets or sets the resources associated with the
        /// current scope, serialized as a JSON array.
        /// </summary>
        public virtual string Resources { get; set; }

        /// <summary>
        /// Gets or sets the entity version, used as a concurrency token.
        /// </summary>
        public virtual int Version { get; set; }
    }
}
