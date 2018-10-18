/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIddict.EntityFrameworkCore
{
    /// <summary>
    /// Defines a relational mapping for the Scope entity.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    /// <typeparam name="TKey">The type of the Key entity.</typeparam>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictScopeConfiguration<TScope, TKey> : IEntityTypeConfiguration<TScope>
        where TScope : OpenIddictScope<TKey>
        where TKey : IEquatable<TKey>
    {
        public void Configure([NotNull] EntityTypeBuilder<TScope> builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            // Warning: optional foreign keys MUST NOT be added as CLR properties because
            // Entity Framework would throw an exception due to the TKey generic parameter
            // being non-nullable when using value types like short, int, long or Guid.

            // If primary/foreign keys are strings, limit their length to ensure
            // they can be safely used in indexes, specially when the underlying
            // provider is known to not restrict the default length (e.g MySQL).
            if (typeof(TKey) == typeof(string))
            {
                builder.Property(scope => scope.Id)
                       .HasMaxLength(50);
            }

            builder.HasKey(scope => scope.Id);

            builder.HasIndex(scope => scope.Name)
                   .IsUnique();

            builder.Property(scope => scope.ConcurrencyToken)
                   .HasMaxLength(50)
                   .IsConcurrencyToken();

            builder.Property(scope => scope.Name)
                   .HasMaxLength(200)
                   .IsRequired();

            builder.ToTable("OpenIddictScopes");
        }
    }
}
