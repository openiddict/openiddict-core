/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Data.Entity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Core;
using OpenIddict.EntityFramework;
using OpenIddict.EntityFramework.Models;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes the necessary methods required to configure the OpenIddict Entity Framework 6.x services.
    /// </summary>
    public class OpenIddictEntityFrameworkBuilder
    {
        /// <summary>
        /// Initializes a new instance of <see cref="OpenIddictEntityFrameworkBuilder"/>.
        /// </summary>
        /// <param name="services">The services collection.</param>
        public OpenIddictEntityFrameworkBuilder(IServiceCollection services)
            => Services = services ?? throw new ArgumentNullException(nameof(services));

        /// <summary>
        /// Gets the services collection.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IServiceCollection Services { get; }

        /// <summary>
        /// Amends the default OpenIddict Entity Framework 6.x configuration.
        /// </summary>
        /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictEntityFrameworkBuilder"/>.</returns>
        public OpenIddictEntityFrameworkBuilder Configure(Action<OpenIddictEntityFrameworkOptions> configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            Services.Configure(configuration);

            return this;
        }

        /// <summary>
        /// Configures OpenIddict to use the specified entities, derived
        /// from the default OpenIddict Entity Framework 6.x entities.
        /// </summary>
        /// <returns>The <see cref="OpenIddictEntityFrameworkBuilder"/>.</returns>
        public OpenIddictEntityFrameworkBuilder ReplaceDefaultEntities<TApplication, TAuthorization, TScope, TToken, TKey>()
            where TApplication : OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TToken>
            where TAuthorization : OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TToken>
            where TScope : OpenIddictEntityFrameworkScope<TKey>
            where TToken : OpenIddictEntityFrameworkToken<TKey, TApplication, TAuthorization>
            where TKey : IEquatable<TKey>
        {
            // Note: unlike Entity Framework Core 1.x/2.x/3.x, Entity Framework 6.x
            // always throws an exception when using generic types as entity types.
            // To ensure a better exception is thrown, a manual check is made here.
            if (typeof(TApplication).IsGenericType || typeof(TAuthorization).IsGenericType ||
                typeof(TScope).IsGenericType || typeof(TToken).IsGenericType)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1276));
            }

            Services.Configure<OpenIddictCoreOptions>(options =>
            {
                options.DefaultApplicationType = typeof(TApplication);
                options.DefaultAuthorizationType = typeof(TAuthorization);
                options.DefaultScopeType = typeof(TScope);
                options.DefaultTokenType = typeof(TToken);
            });

            return this;
        }

        /// <summary>
        /// Configures the OpenIddict Entity Framework 6.x stores to use the specified database context type.
        /// </summary>
        /// <typeparam name="TContext">The type of the <see cref="DbContext"/> used by OpenIddict.</typeparam>
        /// <returns>The <see cref="OpenIddictEntityFrameworkBuilder"/>.</returns>
        public OpenIddictEntityFrameworkBuilder UseDbContext<TContext>()
            where TContext : DbContext
            => UseDbContext(typeof(TContext));

        /// <summary>
        /// Configures the OpenIddict Entity Framework 6.x stores to use the specified database context type.
        /// </summary>
        /// <param name="type">The type of the <see cref="DbContext"/> used by OpenIddict.</param>
        /// <returns>The <see cref="OpenIddictEntityFrameworkBuilder"/>.</returns>
        public OpenIddictEntityFrameworkBuilder UseDbContext(Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (!typeof(DbContext).IsAssignableFrom(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            Services.TryAddScoped(type);

            return Configure(options => options.DbContextType = type);
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="obj">The object to compare with the current object.</param>
        /// <returns><c>true</c> if the specified object is equal to the current object; otherwise, false.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(object? obj) => base.Equals(obj);

        /// <summary>
        /// Serves as the default hash function.
        /// </summary>
        /// <returns>A hash code for the current object.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => base.GetHashCode();

        /// <summary>
        /// Returns a string that represents the current object.
        /// </summary>
        /// <returns>A string that represents the current object.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string? ToString() => base.ToString();
    }
}
