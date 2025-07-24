/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity.Infrastructure.Annotations;
using System.Data.Entity.ModelConfiguration;
using System.Diagnostics.CodeAnalysis;
using System.Linq.Expressions;
using OpenIddict.EntityFramework.Models;

namespace OpenIddict.EntityFramework;

/// <summary>
/// Defines a relational mapping for the Scope entity.
/// </summary>
/// <typeparam name="TScope">The type of the Scope entity.</typeparam>
/// <typeparam name="TKey">The type of the Key entity.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkScopeConfiguration<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TScope,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : EntityTypeConfiguration<TScope>
    where TScope : OpenIddictEntityFrameworkScope<TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkScopeConfiguration()
    {
        // Warning: optional foreign keys MUST NOT be added as CLR properties because
        // Entity Framework would throw an exception due to the TKey generic parameter
        // being non-nullable when using value types like short, int, long or Guid.

        HasKey(static scope => scope.Id);

        Property(static scope => scope.ConcurrencyToken)
            .HasMaxLength(50)
            .IsConcurrencyToken();

        if (typeof(TKey) == typeof(string))
        {
            var parameter = Expression.Parameter(typeof(TScope), "scope");
            var property = Expression.Property(parameter,
                typeof(TScope).GetProperty(nameof(OpenIddictEntityFrameworkScope.Id))!);
            var lambda = Expression.Lambda<Func<TScope, string>>(property, parameter);

            Property(lambda).HasMaxLength(100);
        }

        Property(static scope => scope.Name)
            .HasMaxLength(200)
            .HasColumnAnnotation(IndexAnnotation.AnnotationName, new IndexAnnotation(new IndexAttribute
            {
                IsUnique = true
            }));

        ToTable("OpenIddictScopes");
    }
}
