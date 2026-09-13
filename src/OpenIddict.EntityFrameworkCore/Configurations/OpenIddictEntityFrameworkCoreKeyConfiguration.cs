/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIddict.EntityFrameworkCore;

/// <summary>
/// Defines a relational mapping for the key entity.
/// </summary>
/// <typeparam name="TEntity">The type of the key entity.</typeparam>
/// <typeparam name="TKey">The type of the primary key.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkCoreKeyConfiguration<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TEntity,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IEntityTypeConfiguration<TEntity>
    where TEntity : OpenIddictEntityFrameworkCoreKey<TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public void Configure(EntityTypeBuilder<TEntity> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Property(static key => key.Algorithm)
               .HasMaxLength(50);

        builder.Property(static key => key.ConcurrencyToken)
               .HasMaxLength(50)
               .IsConcurrencyToken();

        builder.HasKey(static key => key.Id);

        builder.Property(static key => key.Id)
               .ValueGeneratedOnAdd();

        if (typeof(TKey) == typeof(string))
        {
            builder.Property(static key => key.Id)
                   .HasMaxLength(100);
        }

        builder.Property(static key => key.KeyId)
               .HasMaxLength(100);

        builder.HasIndex(static key => key.KeyId);

        builder.Property(static key => key.Properties)
               .HasConversion(
                   static value => JsonSerializer.Serialize(value, OpenIddictSerializer.Default.IDictionaryStringJsonElement),
                   static value => JsonSerializer.Deserialize(value, OpenIddictSerializer.Default.IDictionaryStringJsonElement),
                   new ValueComparer<IDictionary<string, JsonElement>>(
                       static (left, right) => ReferenceEquals(left, right) || (left != null && right != null && left.SequenceEqual(right)),
                       static value => value.Aggregate(0, static (hash, value) => HashCode.Combine(hash, value)),
                       static value => value.ToDictionary()));

        builder.Property(static key => key.Status)
               .HasMaxLength(50);

        builder.Property(static key => key.Usage)
               .HasMaxLength(50);

        builder.ToTable("OpenIddictKeys");
    }
}
