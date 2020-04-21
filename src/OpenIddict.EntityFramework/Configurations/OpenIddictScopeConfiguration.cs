/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity.Infrastructure.Annotations;
using System.Data.Entity.ModelConfiguration;
using OpenIddict.EntityFramework.Models;

namespace OpenIddict.EntityFramework
{
    /// <summary>
    /// Defines a relational mapping for the Scope entity.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    /// <typeparam name="TKey">The type of the Key entity.</typeparam>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictScopeConfiguration<TScope, TKey> : EntityTypeConfiguration<TScope>
        where TScope : OpenIddictScope<TKey>
        where TKey : IEquatable<TKey>
    {
        public OpenIddictScopeConfiguration()
        {
            // Warning: optional foreign keys MUST NOT be added as CLR properties because
            // Entity Framework would throw an exception due to the TKey generic parameter
            // being non-nullable when using value types like short, int, long or Guid.

            HasKey(scope => scope.Id);

            Property(scope => scope.ConcurrencyToken)
                .HasMaxLength(50)
                .IsConcurrencyToken();

            Property(scope => scope.Name)
                .HasMaxLength(200)
                .IsRequired()
                .HasColumnAnnotation(IndexAnnotation.AnnotationName, new IndexAnnotation(new IndexAttribute
                {
                    IsUnique = true
                }));

            ToTable("OpenIddictScopes");
        }
    }
}
