/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.Models;

namespace Microsoft.Extensions.DependencyInjection {
    public static class OpenIddictExtensions {
        /// <summary>
        /// Registers the Entity Framework stores. Note: when using the built-in Entity Framework stores,
        /// the entities MUST be derived from the models contained in the OpenIddict.Models package.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddEntityFrameworkCoreStores<TContext>([NotNull] this OpenIddictBuilder builder)
            where TContext : DbContext {
            return builder.AddEntityFrameworkCoreStores<TContext, string>();
        }

        /// <summary>
        /// Registers the Entity Framework stores. Note: when using the built-in Entity Framework stores,
        /// the entities MUST be derived from the models contained in the OpenIddict.Models package.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddEntityFrameworkCoreStores<TContext, TKey>([NotNull] this OpenIddictBuilder builder)
            where TContext : DbContext
            where TKey : IEquatable<TKey> {
            if (builder == null) {
                throw new ArgumentNullException(nameof(builder));
            }

            Debug.Assert(builder.ApplicationType != null &&
                         builder.AuthorizationType != null &&
                         builder.ScopeType != null &&
                         builder.TokenType != null, "The entity types exposed by OpenIddictBuilder shouldn't be null.");

            // Register the application store in the DI container.
            builder.Services.TryAddScoped(
                typeof(IOpenIddictApplicationStore<>).MakeGenericType(builder.ApplicationType),
                typeof(OpenIddictApplicationStore<,,,>).MakeGenericType(
                    /* TApplication: */ builder.ApplicationType,
                    /* TToken: */ builder.TokenType,
                    /* TContext: */ typeof(TContext),
                    /* TKey: */ typeof(TKey)));

            // Register the authorization store in the DI container.
            builder.Services.TryAddScoped(
                typeof(IOpenIddictAuthorizationStore<>).MakeGenericType(builder.AuthorizationType),
                typeof(OpenIddictAuthorizationStore<,,,>).MakeGenericType(
                    /* TAuthorization: */ builder.AuthorizationType,
                    /* TToken: */ builder.TokenType,
                    /* TContext: */ typeof(TContext),
                    /* TKey: */ typeof(TKey)));

            // Register the scope store in the DI container.
            builder.Services.TryAddScoped(
                typeof(IOpenIddictScopeStore<>).MakeGenericType(builder.ScopeType),
                typeof(OpenIddictScopeStore<,,>).MakeGenericType(
                    /* TScope: */ builder.ScopeType,
                    /* TContext: */ typeof(TContext),
                    /* TKey: */ typeof(TKey)));

            // Register the token store in the DI container.
            builder.Services.TryAddScoped(
                typeof(IOpenIddictTokenStore<>).MakeGenericType(builder.TokenType),
                typeof(OpenIddictTokenStore<,,,>).MakeGenericType(
                    /* TToken: */ builder.TokenType,
                    /* TAuthorization: */ builder.AuthorizationType,
                    /* TContext: */ typeof(TContext),
                    /* TKey: */ typeof(TKey)));

            return builder;
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the default OpenIddict models and the default key type (string).
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbContextOptionsBuilder UseOpenIddict([NotNull] this DbContextOptionsBuilder builder) {
            return builder.UseOpenIddict<OpenIddictApplication, OpenIddictAuthorization, OpenIddictScope, OpenIddictToken, string>();
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the default OpenIddict models and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbContextOptionsBuilder UseOpenIddict<TKey>([NotNull] this DbContextOptionsBuilder builder) where TKey : IEquatable<TKey> {
            return builder.UseOpenIddict<OpenIddictApplication<TKey, OpenIddictToken<TKey>>,
                                         OpenIddictAuthorization<TKey, OpenIddictToken<TKey>>,
                                         OpenIddictScope<TKey>,
                                         OpenIddictToken<TKey>, TKey>();
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the specified entities and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbContextOptionsBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>([NotNull] this DbContextOptionsBuilder builder)
            where TApplication : OpenIddictApplication<TKey, TToken>
            where TAuthorization : OpenIddictAuthorization<TKey, TToken>
            where TScope : OpenIddictScope<TKey>
            where TToken : OpenIddictToken<TKey>
            where TKey : IEquatable<TKey> {
            if (builder == null) {
                throw new ArgumentNullException(nameof(builder));
            }

            var extension = new OpenIddictExtension<TApplication, TAuthorization, TScope, TToken, TKey>();
            ((IDbContextOptionsBuilderInfrastructure) builder).AddOrUpdateExtension(extension);

            return builder;
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the default OpenIddict models and the default key type (string).
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static ModelBuilder UseOpenIddict([NotNull] this ModelBuilder builder) {
            return builder.UseOpenIddict<OpenIddictApplication, OpenIddictAuthorization, OpenIddictScope, OpenIddictToken, string>();
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the default OpenIddict models and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static ModelBuilder UseOpenIddict<TKey>([NotNull] this ModelBuilder builder) where TKey : IEquatable<TKey> {
            return builder.UseOpenIddict<OpenIddictApplication<TKey, OpenIddictToken<TKey>>,
                                         OpenIddictAuthorization<TKey, OpenIddictToken<TKey>>,
                                         OpenIddictScope<TKey>,
                                         OpenIddictToken<TKey>, TKey>();
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the specified entities and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static ModelBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>([NotNull] this ModelBuilder builder)
            where TApplication : OpenIddictApplication<TKey, TToken>
            where TAuthorization : OpenIddictAuthorization<TKey, TToken>
            where TScope : OpenIddictScope<TKey>
            where TToken : OpenIddictToken<TKey>
            where TKey : IEquatable<TKey> {
            if (builder == null) {
                throw new ArgumentNullException(nameof(builder));
            }

            // Warning: optional foreign keys MUST NOT be added as CLR properties because
            // Entity Framework would throw an exception due to the TKey generic parameter
            // being non-nullable when using value types like short, int, long or Guid.

            // Configure the TApplication entity.
            builder.Entity<TApplication>(entity => {
                entity.HasKey(application => application.Id);

                entity.HasIndex("ClientId")
                      .IsUnique(unique: true);

                entity.HasMany(application => application.Tokens)
                      .WithOne()
                      .HasForeignKey("ApplicationId")
                      .IsRequired(required: false);

                entity.ToTable("OpenIddictApplications");
            });

            // Configure the TAuthorization entity.
            builder.Entity<TAuthorization>(entity => {
                entity.HasKey(authorization => authorization.Id);

                entity.HasMany(application => application.Tokens)
                      .WithOne()
                      .HasForeignKey("AuthorizationId")
                      .IsRequired(required: false);

                entity.ToTable("OpenIddictAuthorizations");
            });

            // Configure the TScope entity.
            builder.Entity<TScope>(entity => {
                entity.HasKey(scope => scope.Id);

                entity.ToTable("OpenIddictScopes");
            });

            // Configure the TToken entity.
            builder.Entity<TToken>(entity => {
                entity.HasKey(token => token.Id);

                entity.ToTable("OpenIddictTokens");
            });

            return builder;
        }
    }
}