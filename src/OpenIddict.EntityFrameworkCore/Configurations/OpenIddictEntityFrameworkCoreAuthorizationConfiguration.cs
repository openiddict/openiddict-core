/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIddict.EntityFrameworkCore
{
    /// <summary>
    /// Defines a relational mapping for the Authorization entity.
    /// </summary>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TKey">The type of the Key entity.</typeparam>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictEntityFrameworkCoreAuthorizationConfiguration<TAuthorization, TApplication, TToken, TKey> : IEntityTypeConfiguration<TAuthorization>
        where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
        where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
        where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
        where TKey : IEquatable<TKey>
    {
        public void Configure(EntityTypeBuilder<TAuthorization> builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            // Warning: optional foreign keys MUST NOT be added as CLR properties because
            // Entity Framework would throw an exception due to the TKey generic parameter
            // being non-nullable when using value types like short, int, long or Guid.

            builder.HasKey(authorization => authorization.Id);

            builder.HasIndex(
                nameof(OpenIddictEntityFrameworkCoreAuthorization.Application) + nameof(OpenIddictEntityFrameworkCoreApplication.Id),
                nameof(OpenIddictEntityFrameworkCoreAuthorization.Status),
                nameof(OpenIddictEntityFrameworkCoreAuthorization.Subject),
                nameof(OpenIddictEntityFrameworkCoreAuthorization.Type));

            builder.Property(authorization => authorization.ConcurrencyToken)
                   .HasMaxLength(50)
                   .IsConcurrencyToken();

            builder.Property(authorization => authorization.Id!)
                   .ValueGeneratedOnAdd();

            builder.Property(authorization => authorization.Status)
                   .HasMaxLength(25);

            builder.Property(authorization => authorization.Subject)
                   .HasMaxLength(450);

            builder.Property(authorization => authorization.Type)
                   .HasMaxLength(25);

            builder.HasMany(authorization => authorization.Tokens)
                   .WithOne(token => token.Authorization!)
                   .HasForeignKey(nameof(OpenIddictEntityFrameworkCoreToken.Authorization) +
                                  nameof(OpenIddictEntityFrameworkCoreAuthorization.Id))
                   .IsRequired(required: false);

            builder.ToTable("OpenIddictAuthorizations");
        }
    }
}
