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
/// Defines a relational mapping for the token entity.
/// </summary>
/// <typeparam name="TToken">The type of the token entity.</typeparam>
/// <typeparam name="TApplication">The type of the application entity.</typeparam>
/// <typeparam name="TAuthorization">The type of the authorization entity.</typeparam>
/// <typeparam name="TSession">The type of the session entity.</typeparam>
/// <typeparam name="TKey">The type of the primary key.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkTokenConfiguration<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TSession,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : EntityTypeConfiguration<TToken>
    where TToken : OpenIddictEntityFrameworkToken<TKey, TApplication, TAuthorization, TSession>
    where TApplication : OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TSession, TToken>
    where TAuthorization : OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TSession, TToken>
    where TSession : OpenIddictEntityFrameworkSession<TKey, TApplication, TAuthorization, TToken>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkTokenConfiguration()
    {
        // Warning: optional foreign keys MUST NOT be added as CLR properties because
        // Entity Framework would throw an exception due to the TKey generic parameter
        // being non-nullable when using value types like short, int, long or Guid.

        Property(static token => token.ConcurrencyToken)
            .HasMaxLength(50)
            .IsConcurrencyToken();

        HasKey(static token => token.Id);

        if (typeof(TKey) == typeof(string))
        {
            var parameter = Expression.Parameter(typeof(TToken), "token");
            var property = Expression.Property(parameter,
                typeof(TToken).GetProperty(nameof(OpenIddictEntityFrameworkToken.Id))!);
            var lambda = Expression.Lambda<Func<TToken, string>>(property, parameter);

            Property(lambda).HasMaxLength(100);
        }

        Property(static token => token.ReferenceId)
            .HasMaxLength(100);

        // Warning: the index on the ReferenceId property MUST NOT be declared as
        // a unique index, as Entity Framework 6.x doesn't support creating indexes
        // with null-friendly WHERE conditions, unlike Entity Framework Core.
        HasIndex(static token => token.ReferenceId);

        Property(static token => token.Status)
            .HasMaxLength(50);

        Property(static token => token.Subject)
            .HasMaxLength(400);

        Property(static token => token.Type)
            .HasMaxLength(150);

        ToTable("OpenIddictTokens");
    }
}
