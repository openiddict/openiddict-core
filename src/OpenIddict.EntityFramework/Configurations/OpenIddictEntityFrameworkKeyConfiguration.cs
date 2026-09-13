/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Data.Entity.ModelConfiguration;
using System.Diagnostics.CodeAnalysis;
using System.Linq.Expressions;
using OpenIddict.EntityFramework.Models;

namespace OpenIddict.EntityFramework;

/// <summary>
/// Defines a relational mapping for the key entity.
/// </summary>
/// <typeparam name="TEntity">The type of the key entity.</typeparam>
/// <typeparam name="TKey">The type of the primary key.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkKeyConfiguration<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TEntity,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : EntityTypeConfiguration<TEntity>
    where TEntity : OpenIddictEntityFrameworkKey<TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkKeyConfiguration()
    {
        Property(static key => key.Algorithm)
            .HasMaxLength(50);

        Property(static key => key.ConcurrencyToken)
            .HasMaxLength(50)
            .IsConcurrencyToken();

        HasKey(static key => key.Id);

        if (typeof(TKey) == typeof(string))
        {
            var parameter = Expression.Parameter(typeof(TEntity), "key");
            var property = Expression.Property(parameter,
                typeof(TEntity).GetProperty(nameof(OpenIddictEntityFrameworkKey.Id))!);
            var lambda = Expression.Lambda<Func<TEntity, string>>(property, parameter);

            Property(lambda).HasMaxLength(100);
        }

        Property(static key => key.KeyId)
            .HasMaxLength(100);

        HasIndex(static key => key.KeyId);

        Property(static key => key.Status)
            .HasMaxLength(50);

        Property(static key => key.Usage)
            .HasMaxLength(50);

        ToTable("OpenIddictKeys");
    }
}
