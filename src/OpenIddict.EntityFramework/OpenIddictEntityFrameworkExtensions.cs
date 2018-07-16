/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity;
using System.Data.Entity.Infrastructure.Annotations;
using System.Text;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.EntityFramework;
using OpenIddict.EntityFramework.Models;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OpenIddictEntityFrameworkExtensions
    {
        /// <summary>
        /// Registers the Entity Framework 6.x stores services in the DI container and
        /// configures OpenIddict to use the Entity Framework 6.x entities by default.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictEntityFrameworkBuilder"/>.</returns>
        public static OpenIddictEntityFrameworkBuilder UseEntityFramework([NotNull] this OpenIddictCoreBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.SetDefaultApplicationEntity<OpenIddictApplication>()
                   .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                   .SetDefaultScopeEntity<OpenIddictScope>()
                   .SetDefaultTokenEntity<OpenIddictToken>();

            builder.ReplaceApplicationStoreResolver<OpenIddictApplicationStoreResolver>()
                   .ReplaceAuthorizationStoreResolver<OpenIddictAuthorizationStoreResolver>()
                   .ReplaceScopeStoreResolver<OpenIddictScopeStoreResolver>()
                   .ReplaceTokenStoreResolver<OpenIddictTokenStoreResolver>();

            builder.Services.TryAddScoped(typeof(OpenIddictApplicationStore<,,,,>));
            builder.Services.TryAddScoped(typeof(OpenIddictAuthorizationStore<,,,,>));
            builder.Services.TryAddScoped(typeof(OpenIddictScopeStore<,,>));
            builder.Services.TryAddScoped(typeof(OpenIddictTokenStore<,,,,>));

            return new OpenIddictEntityFrameworkBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the Entity Framework 6.x stores services in the DI container and
        /// configures OpenIddict to use the Entity Framework 6.x entities by default.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the Entity Framework 6.x services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public static OpenIddictCoreBuilder UseEntityFramework(
            [NotNull] this OpenIddictCoreBuilder builder,
            [NotNull] Action<OpenIddictEntityFrameworkBuilder> configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration(builder.UseEntityFramework());

            return builder;
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the default OpenIddict models and the default key type (string).
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbModelBuilder UseOpenIddict([NotNull] this DbModelBuilder builder)
            => builder.UseOpenIddict<OpenIddictApplication,
                                     OpenIddictAuthorization,
                                     OpenIddictScope,
                                     OpenIddictToken, string>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework context
        /// using the specified entities and the specified key type.
        /// Note: using this method requires creating non-generic derived classes
        /// for all the OpenIddict entities (application, authorization, scope, token).
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbModelBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>([NotNull] this DbModelBuilder builder)
            where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>
            where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>
            where TScope : OpenIddictScope<TKey>
            where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>
            where TKey : IEquatable<TKey>
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            // Note: unlike Entity Framework 6.x 1.x/2.x, Entity Framework 6.x
            // always throws an exception when using generic types as entity types.
            // To ensure a better exception is thrown, a manual check is made here.
            if (typeof(TApplication).IsGenericType)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The application entity cannot be a generic type.")
                    .Append("Consider creating a non-generic derived class.")
                    .ToString());
            }

            if (typeof(TAuthorization).IsGenericType)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The authorization entity cannot be a generic type.")
                    .Append("Consider creating a non-generic derived class.")
                    .ToString());
            }

            if (typeof(TScope).IsGenericType)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The scope entity cannot be a generic type.")
                    .Append("Consider creating a non-generic derived class.")
                    .ToString());
            }

            if (typeof(TToken).IsGenericType)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The token entity cannot be a generic type.")
                    .Append("Consider creating a non-generic derived class.")
                    .ToString());
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
                   .Map(association => association.MapKey("AuthorizationId"))
                   .WillCascadeOnDelete();

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
                   .IsRequired()
                   .HasMaxLength(450)
                   .HasColumnAnnotation(IndexAnnotation.AnnotationName, new IndexAnnotation(new IndexAttribute()));

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
    }
}