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
/// Defines a relational mapping for the session entity.
/// </summary>
/// <typeparam name="TSession">The type of the session entity.</typeparam>
/// <typeparam name="TApplication">The type of the application entity.</typeparam>
/// <typeparam name="TAuthorization">The type of the authorization entity.</typeparam>
/// <typeparam name="TToken">The type of the token entity.</typeparam>
/// <typeparam name="TKey">The type of the primary key.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkSessionConfiguration<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TSession,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : EntityTypeConfiguration<TSession>
    where TSession : OpenIddictEntityFrameworkSession<TKey, TApplication, TAuthorization>
    where TApplication : OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TToken>
    where TAuthorization : OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TToken>
    where TToken : OpenIddictEntityFrameworkToken<TKey, TApplication, TAuthorization>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkSessionConfiguration()
    {
        // Warning: optional foreign keys MUST NOT be added as CLR properties because
        // Entity Framework would throw an exception due to the TKey generic parameter
        // being non-nullable when using value types like short, int, long or Guid.

        Property(static session => session.ConcurrencyToken)
            .HasMaxLength(50)
            .IsConcurrencyToken();

        HasKey(static session => session.Id);

        if (typeof(TKey) == typeof(string))
        {
            var parameter = Expression.Parameter(typeof(TSession), "session");
            var property = Expression.Property(parameter,
                typeof(TSession).GetProperty(nameof(OpenIddictEntityFrameworkSession.Id))!);
            var lambda = Expression.Lambda<Func<TSession, string>>(property, parameter);

            Property(lambda).HasMaxLength(100);
        }

        Property(static session => session.LoginId)
            .HasMaxLength(100);

        HasIndex(static session => session.LoginId);

        Property(static session => session.Status)
            .HasMaxLength(50);

        Property(static session => session.Subject)
            .HasMaxLength(400);

        ToTable("OpenIddictSessions");
    }
}
