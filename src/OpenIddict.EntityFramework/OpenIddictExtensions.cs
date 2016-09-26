/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict;

namespace Microsoft.AspNetCore.Builder {
    public static class OpenIddictExtensions {
        /// <summary>
        /// Registers the Entity Framework stores.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddEntityFramework<TContext>([NotNull] this OpenIddictBuilder builder)
            where TContext : DbContext {
            return builder.AddEntityFramework<TContext, string>();
        }

        /// <summary>
        /// Registers the Entity Framework stores.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddEntityFramework<TContext, TKey>([NotNull] this OpenIddictBuilder builder)
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
    }
}