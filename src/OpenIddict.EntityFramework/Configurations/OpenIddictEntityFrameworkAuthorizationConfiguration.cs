/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Data.Entity.ModelConfiguration;
using OpenIddict.EntityFramework.Models;

namespace OpenIddict.EntityFramework
{
    /// <summary>
    /// Defines a relational mapping for the Authorization entity.
    /// </summary>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TKey">The type of the Key entity.</typeparam>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictEntityFrameworkAuthorizationConfiguration<TAuthorization, TApplication, TToken, TKey> : EntityTypeConfiguration<TAuthorization>
        where TAuthorization : OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TToken>
        where TApplication : OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TToken>
        where TToken : OpenIddictEntityFrameworkToken<TKey, TApplication, TAuthorization>
        where TKey : IEquatable<TKey>
    {
        public OpenIddictEntityFrameworkAuthorizationConfiguration()
        {
            // Warning: optional foreign keys MUST NOT be added as CLR properties because
            // Entity Framework would throw an exception due to the TKey generic parameter
            // being non-nullable when using value types like short, int, long or Guid.

            HasKey(authorization => authorization.Id);

            Property(authorization => authorization.ConcurrencyToken)
                .HasMaxLength(50)
                .IsConcurrencyToken();

            Property(authorization => authorization.Status)
                .HasMaxLength(25)
                .IsRequired();

            Property(authorization => authorization.Subject)
                .HasMaxLength(450);

            Property(authorization => authorization.Type)
                .HasMaxLength(25)
                .IsRequired();

            HasMany(authorization => authorization.Tokens)
                .WithOptional(token => token.Authorization)
                .Map(association => association.MapKey(nameof(OpenIddictEntityFrameworkToken.Authorization) +
                                                       nameof(OpenIddictEntityFrameworkAuthorization.Id)))
                .WillCascadeOnDelete();

            ToTable("OpenIddictAuthorizations");
        }
    }
}
