/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.Models;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OpenIddictExtensions
    {
        /// <summary>
        /// Registers the Entity Framework Core stores. Note: when using the Entity Framework Core stores,
        /// the entities MUST be derived from the models contained in the OpenIddict.Models package.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public static OpenIddictCoreBuilder AddEntityFrameworkCoreStores<TContext>([NotNull] this OpenIddictCoreBuilder builder)
            where TContext : DbContext
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.TryAddScoped(typeof(OpenIddictApplicationStore<,,,,>));
            builder.Services.TryAddScoped(typeof(OpenIddictAuthorizationStore<,,,,>));
            builder.Services.TryAddScoped(typeof(OpenIddictScopeStore<,,>));
            builder.Services.TryAddScoped(typeof(OpenIddictTokenStore<,,,,>));

            return builder.ReplaceApplicationStoreResolver<OpenIddictApplicationStoreResolver<TContext>>()
                          .ReplaceAuthorizationStoreResolver<OpenIddictAuthorizationStoreResolver<TContext>>()
                          .ReplaceScopeStoreResolver<OpenIddictScopeStoreResolver<TContext>>()
                          .ReplaceTokenStoreResolver<OpenIddictTokenStoreResolver<TContext>>();
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the default OpenIddict models and the default key type (string).
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbContextOptionsBuilder UseOpenIddict([NotNull] this DbContextOptionsBuilder builder)
            => builder.UseOpenIddict<OpenIddictApplication,
                                     OpenIddictAuthorization,
                                     OpenIddictScope,
                                     OpenIddictToken, string>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the default OpenIddict models and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbContextOptionsBuilder UseOpenIddict<TKey>([NotNull] this DbContextOptionsBuilder builder)
            where TKey : IEquatable<TKey>
            => builder.UseOpenIddict<OpenIddictApplication<TKey>,
                                     OpenIddictAuthorization<TKey>,
                                     OpenIddictScope<TKey>,
                                     OpenIddictToken<TKey>, TKey>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the specified entities and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbContextOptionsBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>([NotNull] this DbContextOptionsBuilder builder)
            where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>, new()
            where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>, new()
            where TScope : OpenIddictScope<TKey>, new()
            where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>, new()
            where TKey : IEquatable<TKey>
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.ReplaceService<IModelCustomizer, OpenIddictCustomizer<TApplication, TAuthorization, TScope, TToken, TKey>>();
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the default OpenIddict models and the default key type (string).
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static ModelBuilder UseOpenIddict([NotNull] this ModelBuilder builder)
            => builder.UseOpenIddict<OpenIddictApplication,
                                     OpenIddictAuthorization,
                                     OpenIddictScope,
                                     OpenIddictToken, string>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the default OpenIddict models and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static ModelBuilder UseOpenIddict<TKey>([NotNull] this ModelBuilder builder) where TKey : IEquatable<TKey>
            => builder.UseOpenIddict<OpenIddictApplication<TKey>,
                                     OpenIddictAuthorization<TKey>,
                                     OpenIddictScope<TKey>,
                                     OpenIddictToken<TKey>, TKey>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the specified entities and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static ModelBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>([NotNull] this ModelBuilder builder)
            where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>, new()
            where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>, new()
            where TScope : OpenIddictScope<TKey>, new()
            where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>, new()
            where TKey : IEquatable<TKey>
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            // Warning: optional foreign keys MUST NOT be added as CLR properties because
            // Entity Framework would throw an exception due to the TKey generic parameter
            // being non-nullable when using value types like short, int, long or Guid.

            // Configure the TApplication entity.
            builder.Entity<TApplication>(entity =>
            {
                entity.HasKey(application => application.Id);

                entity.HasIndex(application => application.ClientId)
                      .IsUnique();

                entity.Property(application => application.ClientId)
                      .IsRequired();

                entity.Property(application => application.ConcurrencyToken)
                      .IsConcurrencyToken();

                entity.Property(application => application.Type)
                      .IsRequired();

                entity.HasMany(application => application.Authorizations)
                      .WithOne(authorization => authorization.Application)
                      .HasForeignKey("ApplicationId")
                      .IsRequired(required: false);

                entity.HasMany(application => application.Tokens)
                      .WithOne(token => token.Application)
                      .HasForeignKey("ApplicationId")
                      .IsRequired(required: false);

                entity.ToTable("OpenIddictApplications");
            });

            // Configure the TAuthorization entity.
            builder.Entity<TAuthorization>(entity =>
            {
                entity.HasKey(authorization => authorization.Id);

                entity.Property(authorization => authorization.ConcurrencyToken)
                      .IsConcurrencyToken();

                entity.Property(authorization => authorization.Status)
                      .IsRequired();

                entity.Property(authorization => authorization.Subject)
                      .IsRequired();

                entity.Property(authorization => authorization.Type)
                      .IsRequired();

                entity.HasMany(authorization => authorization.Tokens)
                      .WithOne(token => token.Authorization)
                      .HasForeignKey("AuthorizationId")
                      .IsRequired(required: false)
                      .OnDelete(DeleteBehavior.Cascade);

                entity.ToTable("OpenIddictAuthorizations");
            });

            // Configure the TScope entity.
            builder.Entity<TScope>(entity =>
            {
                entity.HasKey(scope => scope.Id);

                entity.HasIndex(scope => scope.Name)
                      .IsUnique();

                entity.Property(scope => scope.ConcurrencyToken)
                      .IsConcurrencyToken();

                entity.Property(scope => scope.Name)
                      .IsRequired();

                entity.ToTable("OpenIddictScopes");
            });

            // Configure the TToken entity.
            builder.Entity<TToken>(entity =>
            {
                entity.HasKey(token => token.Id);

                entity.HasIndex(token => token.ReferenceId)
                      .IsUnique();

                entity.Property(token => token.ConcurrencyToken)
                      .IsConcurrencyToken();

                entity.Property(token => token.Subject)
                      .IsRequired();

                entity.Property(token => token.Type)
                      .IsRequired();

                entity.ToTable("OpenIddictTokens");
            });

            return builder;
        }
    }
}