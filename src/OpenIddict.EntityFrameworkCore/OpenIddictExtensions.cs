/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Core;
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
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddEntityFrameworkCoreStores<TContext>([NotNull] this OpenIddictBuilder builder)
            where TContext : DbContext
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            Debug.Assert(builder.ApplicationType != null &&
                         builder.AuthorizationType != null &&
                         builder.ScopeType != null &&
                         builder.TokenType != null, "The entity types exposed by OpenIddictBuilder shouldn't be null.");

            var application = FindGenericBaseType(builder.ApplicationType, typeof(OpenIddictApplication<,,>));
            if (application == null)
            {
                throw new InvalidOperationException("The Entity Framework Core stores can only be used " +
                                                    "with the built-in OpenIddictApplication entity.");
            }

            var authorization = FindGenericBaseType(builder.AuthorizationType, typeof(OpenIddictAuthorization<,,>));
            if (authorization == null)
            {
                throw new InvalidOperationException("The Entity Framework Core stores can only be used " +
                                                    "with the built-in OpenIddictAuthorization entity.");
            }

            var scope = FindGenericBaseType(builder.ScopeType, typeof(OpenIddictScope<>));
            if (scope == null)
            {
                throw new InvalidOperationException("The Entity Framework Core stores can only be used " +
                                                    "with the built-in OpenIddictScope entity.");
            }

            var token = FindGenericBaseType(builder.TokenType, typeof(OpenIddictToken<,,>));
            if (token == null)
            {
                throw new InvalidOperationException("The Entity Framework Core stores can only be used " +
                                                    "with the built-in OpenIddictToken entity.");
            }

            var converter = TypeDescriptor.GetConverter(application.GenericTypeArguments[0]);
            if (converter == null || !converter.CanConvertFrom(typeof(string)) ||
                                     !converter.CanConvertTo(typeof(string)))
            {
                throw new InvalidOperationException("The specified entity key type is not supported.");
            }

            // Register the application store in the DI container.
            builder.Services.TryAddScoped(
                typeof(IOpenIddictApplicationStore<>).MakeGenericType(builder.ApplicationType),
                typeof(OpenIddictApplicationStore<,,,,>).MakeGenericType(
                    /* TApplication: */ builder.ApplicationType,
                    /* TAuthorization: */ builder.AuthorizationType,
                    /* TToken: */ builder.TokenType,
                    /* TContext: */ typeof(TContext),
                    /* TKey: */ application.GenericTypeArguments[0]));

            // Register the authorization store in the DI container.
            builder.Services.TryAddScoped(
                typeof(IOpenIddictAuthorizationStore<>).MakeGenericType(builder.AuthorizationType),
                typeof(OpenIddictAuthorizationStore<,,,,>).MakeGenericType(
                    /* TAuthorization: */ builder.AuthorizationType,
                    /* TApplication: */ builder.ApplicationType,
                    /* TToken: */ builder.TokenType,
                    /* TContext: */ typeof(TContext),
                    /* TKey: */ authorization.GenericTypeArguments[0]));

            // Register the scope store in the DI container.
            builder.Services.TryAddScoped(
                typeof(IOpenIddictScopeStore<>).MakeGenericType(builder.ScopeType),
                typeof(OpenIddictScopeStore<,,>).MakeGenericType(
                    /* TScope: */ builder.ScopeType,
                    /* TContext: */ typeof(TContext),
                    /* TKey: */ scope.GenericTypeArguments[0]));

            // Register the token store in the DI container.
            builder.Services.TryAddScoped(
                typeof(IOpenIddictTokenStore<>).MakeGenericType(builder.TokenType),
                typeof(OpenIddictTokenStore<,,,,>).MakeGenericType(
                    /* TToken: */ builder.TokenType,
                    /* TApplication: */ builder.ApplicationType,
                    /* TAuthorization: */ builder.AuthorizationType,
                    /* TContext: */ typeof(TContext),
                    /* TKey: */ token.GenericTypeArguments[0]));

            return builder;
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the default OpenIddict models and the default key type (string).
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbContextOptionsBuilder UseOpenIddict([NotNull] this DbContextOptionsBuilder builder)
        {
            return builder.UseOpenIddict<OpenIddictApplication,
                                         OpenIddictAuthorization,
                                         OpenIddictScope,
                                         OpenIddictToken, string>();
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the default OpenIddict models and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbContextOptionsBuilder UseOpenIddict<TKey>([NotNull] this DbContextOptionsBuilder builder) where TKey : IEquatable<TKey>
        {
            return builder.UseOpenIddict<OpenIddictApplication<TKey>,
                                         OpenIddictAuthorization<TKey>,
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
        public static ModelBuilder UseOpenIddict([NotNull] this ModelBuilder builder)
        {
            return builder.UseOpenIddict<OpenIddictApplication,
                                         OpenIddictAuthorization,
                                         OpenIddictScope,
                                         OpenIddictToken, string>();
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the default OpenIddict models and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static ModelBuilder UseOpenIddict<TKey>([NotNull] this ModelBuilder builder) where TKey : IEquatable<TKey>
        {
            return builder.UseOpenIddict<OpenIddictApplication<TKey>,
                                         OpenIddictAuthorization<TKey>,
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
                      .IsRequired(required: false);

                entity.ToTable("OpenIddictAuthorizations");
            });

            // Configure the TScope entity.
            builder.Entity<TScope>(entity =>
            {
                entity.HasKey(scope => scope.Id);

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

        private static TypeInfo FindGenericBaseType(Type type, Type definition)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (definition == null)
            {
                throw new ArgumentNullException(nameof(definition));
            }

            for (var candidate = type.GetTypeInfo(); candidate != null; candidate = candidate.BaseType?.GetTypeInfo())
            {
                if (candidate.IsGenericType && candidate.GetGenericTypeDefinition() == definition)
                {
                    return candidate;
                }
            }

            return null;
        }
    }
}