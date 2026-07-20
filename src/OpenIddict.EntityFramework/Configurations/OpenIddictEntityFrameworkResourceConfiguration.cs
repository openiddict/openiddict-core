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
/// Defines a relational mapping for the resource entity.
/// </summary>
/// <typeparam name="TResource">The type of the resource entity.</typeparam>
/// <typeparam name="TKey">The type of the primary key.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkResourceConfiguration<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TResource,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : EntityTypeConfiguration<TResource>
    where TResource : OpenIddictEntityFrameworkResource<TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkResourceConfiguration()
    {
        // Warning: optional foreign keys MUST NOT be added as CLR properties because
        // Entity Framework would throw an exception due to the TKey generic parameter
        // being non-nullable when using value types like short, int, long or Guid.

        HasKey(static resource => resource.Id);

        Property(static resource => resource.ConcurrencyToken)
            .HasMaxLength(50)
            .IsConcurrencyToken();

        if (typeof(TKey) == typeof(string))
        {
            var parameter = Expression.Parameter(typeof(TResource), "resource");
            var property = Expression.Property(parameter,
                typeof(TResource).GetProperty(nameof(OpenIddictEntityFrameworkResource.Id))!);
            var lambda = Expression.Lambda<Func<TResource, string>>(property, parameter);

            Property(lambda).HasMaxLength(100);
        }

        Property(static resource => resource.Name)
            .HasMaxLength(200)
            .HasColumnAnnotation(IndexAnnotation.AnnotationName, new IndexAnnotation(new IndexAttribute
            {
                IsUnique = true
            }));

        ToTable("OpenIddictResources");
    }
}
