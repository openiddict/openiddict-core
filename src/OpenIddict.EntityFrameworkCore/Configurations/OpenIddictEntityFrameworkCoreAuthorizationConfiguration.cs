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
/// Defines a relational mapping for the authorization entity.
/// </summary>
/// <typeparam name="TAuthorization">The type of the authorization entity.</typeparam>
/// <typeparam name="TApplication">The type of the application entity.</typeparam>
/// <typeparam name="TToken">The type of the token entity.</typeparam>
/// <typeparam name="TKey">The type of the primary key.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkCoreAuthorizationConfiguration<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IEntityTypeConfiguration<TAuthorization>
    where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
    where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
    where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
    where TKey : notnull, IEquatable<TKey>
{
    public void Configure(EntityTypeBuilder<TAuthorization> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Warning: optional foreign keys MUST NOT be added as CLR properties because
        // Entity Framework would throw an exception due to the TKey generic parameter
        // being non-nullable when using value types like short, int, long or Guid.

        builder.HasIndex(
            nameof(OpenIddictEntityFrameworkCoreAuthorization.Application) + nameof(OpenIddictEntityFrameworkCoreApplication.Id),
            nameof(OpenIddictEntityFrameworkCoreAuthorization.Status),
            nameof(OpenIddictEntityFrameworkCoreAuthorization.Subject),
            nameof(OpenIddictEntityFrameworkCoreAuthorization.Type));

        builder.Property(static authorization => authorization.ConcurrencyToken)
               .HasMaxLength(50)
               .IsConcurrencyToken();

        builder.HasKey(static authorization => authorization.Id);

        builder.Property(static authorization => authorization.Id)
               .ValueGeneratedOnAdd();

        if (typeof(TKey) == typeof(string))
        {
            builder.Property(static authorization => authorization.Id)
                   .HasMaxLength(100);
        }

        builder.Property(static authorization => authorization.Properties)
               .HasConversion(
                   static value => JsonSerializer.Serialize(value, OpenIddictSerializer.Default.IDictionaryStringJsonElement),
                   static value => JsonSerializer.Deserialize(value, OpenIddictSerializer.Default.IDictionaryStringJsonElement),
                   CreateDictionaryComparer<JsonElement>());

        builder.Property(static authorization => authorization.Status)
               .HasMaxLength(50);

        builder.Property(static authorization => authorization.Subject)
               .HasMaxLength(400);

        builder.HasMany(static authorization => authorization.Tokens)
               .WithOne(static token => token.Authorization!)
               .HasForeignKey(nameof(OpenIddictEntityFrameworkCoreToken.Authorization) +
                              nameof(OpenIddictEntityFrameworkCoreAuthorization.Id))
               .IsRequired(required: false);

        builder.Property(static authorization => authorization.Type)
               .HasMaxLength(50);

        builder.ToTable("OpenIddictAuthorizations");

        static ValueComparer CreateDictionaryComparer<TValue>() => new ValueComparer<IDictionary<string, TValue>>(
            static (left, right) => ReferenceEquals(left, right) || (left != null && right != null && left.SequenceEqual(right)),
            static value => value.Aggregate(0, static (hash, value) => HashCode.Combine(hash, value)),
            static value => value.ToDictionary());
    }
}
