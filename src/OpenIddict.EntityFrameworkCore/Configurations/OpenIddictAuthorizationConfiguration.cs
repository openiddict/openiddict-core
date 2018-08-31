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
    public class OpenIddictAuthorizationConfiguration<TAuthorization, TApplication, TToken, TKey> : IEntityTypeConfiguration<TAuthorization>
        where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>
        where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>
        where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>
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

            builder.HasIndex("ApplicationId",
                nameof(OpenIddictAuthorization.Scopes),
                nameof(OpenIddictAuthorization.Status),
                nameof(OpenIddictAuthorization.Subject),
                nameof(OpenIddictAuthorization.Type));

            builder.Property(authorization => authorization.ConcurrencyToken)
                   .IsConcurrencyToken();

            builder.Property(authorization => authorization.Status)
                   .IsRequired();

            builder.Property(authorization => authorization.Subject)
                   .IsRequired();

            builder.Property(authorization => authorization.Type)
                   .IsRequired();

            builder.HasMany(authorization => authorization.Tokens)
                   .WithOne(token => token.Authorization)
                   .HasForeignKey("AuthorizationId")
                   .IsRequired(required: false);

            builder.ToTable("OpenIddictAuthorizations");
        }
    }
}
