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
using Microsoft.IdentityModel.Tokens;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIddict.EntityFrameworkCore;

/// <summary>
/// Defines a relational mapping for the application entity.
/// </summary>
/// <typeparam name="TApplication">The type of the application entity.</typeparam>
/// <typeparam name="TAuthorization">The type of the authorization entity.</typeparam>
/// <typeparam name="TToken">The type of the token entity.</typeparam>
/// <typeparam name="TKey">The type of the primary key.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkCoreApplicationConfiguration<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IEntityTypeConfiguration<TApplication>
    where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
    where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
    where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
    where TKey : notnull, IEquatable<TKey>
{
    public void Configure(EntityTypeBuilder<TApplication> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Warning: optional foreign keys MUST NOT be added as CLR properties because
        // Entity Framework would throw an exception due to the TKey generic parameter
        // being non-nullable when using value types like short, int, long or Guid.

        builder.Property(static application => application.ApplicationType)
               .HasMaxLength(50);

        builder.HasMany(static application => application.Authorizations)
               .WithOne(static authorization => authorization.Application!)
               .HasForeignKey(nameof(OpenIddictEntityFrameworkCoreAuthorization.Application) +
                              nameof(OpenIddictEntityFrameworkCoreApplication.Id))
               .IsRequired(required: false);

        builder.HasIndex(static application => application.ClientId)
               .IsUnique();

        builder.Property(static application => application.ClientId)
               .HasMaxLength(100);

        builder.Property(static application => application.ClientType)
               .HasMaxLength(50);

        builder.Property(static application => application.ConcurrencyToken)
               .HasMaxLength(50)
               .IsConcurrencyToken();

        builder.Property(static application => application.ConsentType)
               .HasMaxLength(50);

        builder.Property(static application => application.DisplayNames)
               .HasConversion(
                   static value => JsonSerializer.Serialize(value, OpenIddictSerializer.Default.IDictionaryStringString),
                   static value => JsonSerializer.Deserialize(value, OpenIddictSerializer.Default.IDictionaryStringString),
                   CreateDictionaryComparer<string>());

        builder.HasKey(static application => application.Id);

        builder.Property(static application => application.Id)
               .ValueGeneratedOnAdd();

        if (typeof(TKey) == typeof(string))
        {
            builder.Property(static application => application.Id)
                   .HasMaxLength(100);
        }

        builder.Property(static application => application.JsonWebKeySet)
               .HasConversion(
                   static value => JsonSerializer.Serialize(value, OpenIddictSerializer.Default.JsonWebKeySet),
                   static value => JsonWebKeySet.Create(value));

        builder.Property(static application => application.Properties)
               .HasConversion(
                   static value => JsonSerializer.Serialize(value, OpenIddictSerializer.Default.IDictionaryStringJsonElement),
                   static value => JsonSerializer.Deserialize(value, OpenIddictSerializer.Default.IDictionaryStringJsonElement),
                   CreateDictionaryComparer<JsonElement>());

        builder.Property(static application => application.Settings)
               .HasConversion(
                   static value => JsonSerializer.Serialize(value, OpenIddictSerializer.Default.IDictionaryStringString),
                   static value => JsonSerializer.Deserialize(value, OpenIddictSerializer.Default.IDictionaryStringString),
                   CreateDictionaryComparer<string>());

        builder.HasMany(static application => application.Tokens)
               .WithOne(static token => token.Application!)
               .HasForeignKey(nameof(OpenIddictEntityFrameworkCoreToken.Application) + nameof(OpenIddictEntityFrameworkCoreApplication.Id))
               .IsRequired(required: false);

        builder.ToTable("OpenIddictApplications");

        static ValueComparer CreateDictionaryComparer<TValue>() => new ValueComparer<IDictionary<string, TValue>>(
            static (left, right) => ReferenceEquals(left, right) || (left != null && right != null && left.SequenceEqual(right)),
            static value => value.Aggregate(0, static (hash, value) => HashCode.Combine(hash, value)),
            static value => value.ToDictionary());
    }
}
