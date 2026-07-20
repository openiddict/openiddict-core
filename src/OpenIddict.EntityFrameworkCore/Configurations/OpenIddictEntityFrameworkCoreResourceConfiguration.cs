/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIddict.EntityFrameworkCore;

/// <summary>
/// Defines a relational mapping for the resource entity.
/// </summary>
/// <typeparam name="TResource">The type of the resource entity.</typeparam>
/// <typeparam name="TKey">The type of the primary key.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkCoreResourceConfiguration<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TResource,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IEntityTypeConfiguration<TResource>
    where TResource : OpenIddictEntityFrameworkCoreResource<TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public void Configure(EntityTypeBuilder<TResource> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Warning: optional foreign keys MUST NOT be added as CLR properties because
        // Entity Framework would throw an exception due to the TKey generic parameter
        // being non-nullable when using value types like short, int, long or Guid.

        builder.HasKey(static resource => resource.Id);

        builder.HasIndex(static resource => resource.Name)
               .IsUnique();

        builder.Property(static resource => resource.ConcurrencyToken)
               .HasMaxLength(50)
               .IsConcurrencyToken();

        builder.Property(static resource => resource.Id)
               .ValueGeneratedOnAdd();

        if (typeof(TKey) == typeof(string))
        {
            builder.Property(static resource => resource.Id)
                   .HasMaxLength(100);
        }

        builder.Property(static resource => resource.Name)
               .HasMaxLength(200);

        builder.ToTable("OpenIddictResources");
    }
}
