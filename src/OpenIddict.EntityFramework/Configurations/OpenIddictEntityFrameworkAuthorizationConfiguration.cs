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
/// Defines a relational mapping for the authorization entity.
/// </summary>
/// <typeparam name="TAuthorization">The type of the authorization entity.</typeparam>
/// <typeparam name="TApplication">The type of the application entity.</typeparam>
/// <typeparam name="TToken">The type of the token entity.</typeparam>
/// <typeparam name="TKey">The type of the primary key.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkAuthorizationConfiguration<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : EntityTypeConfiguration<TAuthorization>
    where TAuthorization : OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TToken>
    where TApplication : OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TToken>
    where TToken : OpenIddictEntityFrameworkToken<TKey, TApplication, TAuthorization>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkAuthorizationConfiguration()
    {
        // Warning: optional foreign keys MUST NOT be added as CLR properties because
        // Entity Framework would throw an exception due to the TKey generic parameter
        // being non-nullable when using value types like short, int, long or Guid.

        Property(static authorization => authorization.ConcurrencyToken)
            .HasMaxLength(50)
            .IsConcurrencyToken();

        HasKey(static authorization => authorization.Id);

        if (typeof(TKey) == typeof(string))
        {
            var parameter = Expression.Parameter(typeof(TAuthorization), "authorization");
            var property = Expression.Property(parameter,
                typeof(TAuthorization).GetProperty(nameof(OpenIddictEntityFrameworkAuthorization.Id))!);
            var lambda = Expression.Lambda<Func<TAuthorization, string>>(property, parameter);

            Property(lambda).HasMaxLength(100);
        }

        Property(static authorization => authorization.Status)
            .HasMaxLength(50);

        Property(static authorization => authorization.Subject)
            .HasMaxLength(400);

        HasMany(static authorization => authorization.Tokens)
            .WithOptional(static token => token.Authorization!)
            .Map(static association => association.MapKey(nameof(OpenIddictEntityFrameworkToken.Authorization) +
                                                          nameof(OpenIddictEntityFrameworkAuthorization.Id)))
            .WillCascadeOnDelete();

        Property(static authorization => authorization.Type)
            .HasMaxLength(50);

        ToTable("OpenIddictAuthorizations");
    }
}
