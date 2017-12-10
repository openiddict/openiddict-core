/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity;
using System.Data.Entity.Infrastructure.Annotations;
using System.Diagnostics;
using System.Reflection;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Core;
using OpenIddict.EntityFramework;
using OpenIddict.Models;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OpenIddictExtensions
    {
        /// <summary>
        /// Registers the Entity Framework 6.x stores. Note: when using the Entity Framework stores,
        /// the application <see cref="DbContext"/> MUST be manually registered in the DI container and
        /// the entities MUST be derived from the models contained in the OpenIddict.Models package.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddEntityFrameworkStores<TContext>([NotNull] this OpenIddictBuilder builder)
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
                throw new InvalidOperationException("The Entity Framework stores can only be used " +
                                                    "with the built-in OpenIddictApplication entity.");
            }

            var authorization = FindGenericBaseType(builder.AuthorizationType, typeof(OpenIddictAuthorization<,,>));
            if (authorization == null)
            {
                throw new InvalidOperationException("The Entity Framework stores can only be used " +
                                                    "with the built-in OpenIddictAuthorization entity.");
            }

            var scope = FindGenericBaseType(builder.ScopeType, typeof(OpenIddictScope<>));
            if (scope == null)
            {
                throw new InvalidOperationException("The Entity Framework stores can only be used " +
                                                    "with the built-in OpenIddictScope entity.");
            }

            var token = FindGenericBaseType(builder.TokenType, typeof(OpenIddictToken<,,>));
            if (token == null)
            {
                throw new InvalidOperationException("The Entity Framework stores can only be used " +
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
        public static DbModelBuilder UseOpenIddict([NotNull] this DbModelBuilder builder)
        {
            return builder.UseOpenIddict<OpenIddictApplication,
                                         OpenIddictAuthorization,
                                         OpenIddictScope,
                                         OpenIddictToken, string>();
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the specified entities and the specified key type.
        /// Note: using this method requires creating non-generic derived classes
        /// for all the OpenIddict entities (application, authorization, scope, token).
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbModelBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>([NotNull] this DbModelBuilder builder)
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

            // Note: unlike Entity Framework Core 1.x/2.x, Entity Framework 6.x
            // always throws an exception when using generic types as entity types.
            // To ensure a better exception is thrown, a manual check is made here.
            if (typeof(TApplication).GetTypeInfo().IsGenericType)
            {
                throw new InvalidOperationException("The application entity cannot be a generic type. " +
                                                    "Consider creating a non-generic derived class.");
            }

            if (typeof(TAuthorization).GetTypeInfo().IsGenericType)
            {
                throw new InvalidOperationException("The authorization entity cannot be a generic type. " +
                                                    "Consider creating a non-generic derived class.");
            }

            if (typeof(TScope).GetTypeInfo().IsGenericType)
            {
                throw new InvalidOperationException("The scope entity cannot be a generic type. " +
                                                    "Consider creating a non-generic derived class.");
            }

            if (typeof(TToken).GetTypeInfo().IsGenericType)
            {
                throw new InvalidOperationException("The scope entity cannot be a generic type. " +
                                                    "Consider creating a non-generic derived class.");
            }

            // Warning: optional foreign keys MUST NOT be added as CLR properties because
            // Entity Framework would throw an exception due to the TKey generic parameter
            // being non-nullable when using value types like short, int, long or Guid.

            // Configure the TApplication entity.
            builder.Entity<TApplication>()
                   .HasKey(application => application.Id);

            builder.Entity<TApplication>()
                   .Property(application => application.ClientId)
                   .IsRequired()
                   .HasMaxLength(450)
                   .HasColumnAnnotation(IndexAnnotation.AnnotationName, new IndexAnnotation(new IndexAttribute()));

            builder.Entity<TApplication>()
                   .Property(application => application.ConcurrencyToken)
                   .IsConcurrencyToken();

            builder.Entity<TApplication>()
                   .Property(application => application.Type)
                   .IsRequired();

            builder.Entity<TApplication>()
                   .HasMany(application => application.Authorizations)
                   .WithOptional(authorization => authorization.Application)
                   .Map(association => association.MapKey("ApplicationId"));

            builder.Entity<TApplication>()
                   .HasMany(application => application.Tokens)
                   .WithOptional(token => token.Application)
                   .Map(association => association.MapKey("ApplicationId"));

            builder.Entity<TApplication>()
                   .ToTable("OpenIddictApplications");

            // Configure the TAuthorization entity.
            builder.Entity<TAuthorization>()
                   .HasKey(authorization => authorization.Id);

            builder.Entity<TAuthorization>()
                   .Property(authorization => authorization.ConcurrencyToken)
                   .IsConcurrencyToken();

            builder.Entity<TAuthorization>()
                   .Property(authorization => authorization.Status)
                   .IsRequired();

            builder.Entity<TAuthorization>()
                   .Property(authorization => authorization.Subject)
                   .IsRequired();

            builder.Entity<TAuthorization>()
                   .Property(authorization => authorization.Type)
                   .IsRequired();

            builder.Entity<TAuthorization>()
                   .HasMany(application => application.Tokens)
                   .WithOptional(token => token.Authorization)
                   .Map(association => association.MapKey("AuthorizationId"));

            builder.Entity<TAuthorization>()
                   .ToTable("OpenIddictAuthorizations");

            // Configure the TScope entity.
            builder.Entity<TScope>()
                   .HasKey(scope => scope.Id);

            builder.Entity<TScope>()
                   .Property(scope => scope.ConcurrencyToken)
                   .IsConcurrencyToken();

            builder.Entity<TScope>()
                   .Property(scope => scope.Name)
                   .IsRequired();

            builder.Entity<TScope>()
                   .ToTable("OpenIddictScopes");

            // Configure the TToken entity.
            builder.Entity<TToken>()
                   .HasKey(token => token.Id);

            builder.Entity<TToken>()
                   .Property(token => token.ConcurrencyToken)
                   .IsConcurrencyToken();

            builder.Entity<TToken>()
                   .Property(token => token.ReferenceId)
                   .HasMaxLength(450)
                   .HasColumnAnnotation(IndexAnnotation.AnnotationName, new IndexAnnotation(new IndexAttribute()));

            builder.Entity<TToken>()
                   .Property(token => token.Subject)
                   .IsRequired();

            builder.Entity<TToken>()
                   .Property(token => token.Type)
                   .IsRequired();

            builder.Entity<TToken>()
                   .ToTable("OpenIddictTokens");

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