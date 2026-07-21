/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIddict.EntityFrameworkCore;

/// <summary>
/// Defines a relational mapping for the scope entity.
/// </summary>
/// <typeparam name="TScope">The type of the scope entity.</typeparam>
/// <typeparam name="TKey">The type of the primary key.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkCoreScopeConfiguration<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TScope,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IEntityTypeConfiguration<TScope>
    where TScope : OpenIddictEntityFrameworkCoreScope<TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public void Configure(EntityTypeBuilder<TScope> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Warning: optional foreign keys MUST NOT be added as CLR properties because
        // Entity Framework would throw an exception due to the TKey generic parameter
        // being non-nullable when using value types like short, int, long or Guid.

        builder.Property(static scope => scope.ConcurrencyToken)
               .HasMaxLength(50)
               .IsConcurrencyToken();

        builder.Property(static scope => scope.Descriptions)
               .HasConversion(
                   static value => JsonSerializer.Serialize(value, OpenIddictSerializer.Default.IDictionaryStringString),
                   static value => JsonSerializer.Deserialize(value, OpenIddictSerializer.Default.IDictionaryStringString));

        builder.Property(static scope => scope.DisplayNames)
               .HasConversion(
                   static value => JsonSerializer.Serialize(value, OpenIddictSerializer.Default.IDictionaryStringString),
                   static value => JsonSerializer.Deserialize(value, OpenIddictSerializer.Default.IDictionaryStringString));

        builder.HasKey(static scope => scope.Id);

        builder.Property(static scope => scope.Id)
               .ValueGeneratedOnAdd();

        if (typeof(TKey) == typeof(string))
        {
            builder.Property(static scope => scope.Id)
                   .HasMaxLength(100);
        }

        builder.Property(static scope => scope.Name)
               .HasMaxLength(200);

        builder.HasIndex(static scope => scope.Name)
               .IsUnique();

        builder.Property(static scope => scope.Properties)
               .HasConversion(
                   static value => JsonSerializer.Serialize(value, OpenIddictSerializer.Default.IDictionaryStringJsonElement),
                   static value => JsonSerializer.Deserialize(value, OpenIddictSerializer.Default.IDictionaryStringJsonElement));

        builder.ToTable("OpenIddictScopes");
    }
}
