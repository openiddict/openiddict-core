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
/// Defines a relational mapping for the session entity.
/// </summary>
/// <typeparam name="TSession">The type of the session entity.</typeparam>
/// <typeparam name="TApplication">The type of the application entity.</typeparam>
/// <typeparam name="TAuthorization">The type of the authorization entity.</typeparam>
/// <typeparam name="TToken">The type of the token entity.</typeparam>
/// <typeparam name="TKey">The type of the primary key.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkCoreSessionConfiguration<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TSession,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IEntityTypeConfiguration<TSession>
    where TSession : OpenIddictEntityFrameworkCoreSession<TKey, TApplication, TAuthorization>
    where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
    where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
    where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
    where TKey : notnull, IEquatable<TKey>
{
    public void Configure(EntityTypeBuilder<TSession> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Warning: optional foreign keys MUST NOT be added as CLR properties because
        // Entity Framework would throw an exception due to the TKey generic parameter
        // being non-nullable when using value types like short, int, long or Guid.

        builder.Property(static session => session.ConcurrencyToken)
               .HasMaxLength(50)
               .IsConcurrencyToken();

        builder.HasKey(static session => session.Id);

        builder.Property(static session => session.Id)
               .ValueGeneratedOnAdd();

        if (typeof(TKey) == typeof(string))
        {
            builder.Property(static session => session.Id)
                   .HasMaxLength(100);
        }

        builder.Property(static session => session.LoginId)
               .HasMaxLength(100);

        builder.HasIndex(static session => session.LoginId);

        builder.Property(static session => session.Status)
               .HasMaxLength(50);

        builder.Property(static session => session.Subject)
               .HasMaxLength(400);

        builder.Property(static session => session.Properties)
               .HasConversion(
                   static value => JsonSerializer.Serialize(value, OpenIddictSerializer.Default.IDictionaryStringJsonElement),
                   static value => JsonSerializer.Deserialize(value, OpenIddictSerializer.Default.IDictionaryStringJsonElement),
                   CreateDictionaryComparer<JsonElement>());

        builder.ToTable("OpenIddictSessions");

        static ValueComparer CreateDictionaryComparer<TValue>() => new ValueComparer<IDictionary<string, TValue>>(
            static (left, right) => ReferenceEquals(left, right) || (left != null && right != null && left.SequenceEqual(right)),
            static value => value.Aggregate(0, static (hash, value) => HashCode.Combine(hash, value)),
            static value => value.ToDictionary());
    }
}
