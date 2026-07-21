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
/// Defines a relational mapping for the token entity.
/// </summary>
/// <typeparam name="TToken">The type of the token entity.</typeparam>
/// <typeparam name="TApplication">The type of the application entity.</typeparam>
/// <typeparam name="TAuthorization">The type of the authorization entity.</typeparam>
/// <typeparam name="TKey">The type of the primary key.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkCoreTokenConfiguration<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IEntityTypeConfiguration<TToken>
    where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
    where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
    where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
    where TKey : notnull, IEquatable<TKey>
{
    public void Configure(EntityTypeBuilder<TToken> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Warning: optional foreign keys MUST NOT be added as CLR properties because
        // Entity Framework would throw an exception due to the TKey generic parameter
        // being non-nullable when using value types like short, int, long or Guid.

        builder.HasIndex(
            nameof(OpenIddictEntityFrameworkCoreToken.Application) + nameof(OpenIddictEntityFrameworkCoreApplication.Id),
            nameof(OpenIddictEntityFrameworkCoreToken.Status),
            nameof(OpenIddictEntityFrameworkCoreToken.Subject),
            nameof(OpenIddictEntityFrameworkCoreToken.Type));

        builder.Property(static token => token.ConcurrencyToken)
               .HasMaxLength(50)
               .IsConcurrencyToken();

        builder.HasKey(static token => token.Id);

        builder.Property(static token => token.Id)
               .ValueGeneratedOnAdd();

        if (typeof(TKey) == typeof(string))
        {
            builder.Property(static token => token.Id)
                   .HasMaxLength(100);
        }

        builder.Property(static token => token.ReferenceId)
               .HasMaxLength(100);

        builder.HasIndex(static token => token.ReferenceId)
               .IsUnique();

        builder.Property(static token => token.Status)
               .HasMaxLength(50);

        builder.Property(static token => token.Subject)
               .HasMaxLength(400);

        builder.Property(static token => token.Properties)
               .HasConversion(
                   static value => JsonSerializer.Serialize(value, OpenIddictSerializer.Default.IDictionaryStringJsonElement),
                   static value => JsonSerializer.Deserialize(value, OpenIddictSerializer.Default.IDictionaryStringJsonElement));

        builder.Property(static token => token.Type)
               .HasMaxLength(150);

        builder.ToTable("OpenIddictTokens");
    }
}
