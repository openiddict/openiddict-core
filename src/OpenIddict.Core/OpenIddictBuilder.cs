/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using JetBrains.Annotations;
using OpenIddict.Core;
using OpenIddict.Models;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes the necessary methods required to configure OpenIddict.
    /// </summary>
    public class OpenIddictBuilder
    {
        /// <summary>
        /// Initializes a new instance of <see cref="OpenIddictBuilder"/>.
        /// </summary>
        /// <param name="services">The services collection.</param>
        public OpenIddictBuilder([NotNull] IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            Services = services;
        }

        /// <summary>
        /// Gets or sets the type corresponding to the Application entity.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Type ApplicationType { get; set; } = typeof(OpenIddictApplication);

        /// <summary>
        /// Gets or sets the type corresponding to the Authorization entity.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Type AuthorizationType { get; set; } = typeof(OpenIddictAuthorization);

        /// <summary>
        /// Gets or sets the type corresponding to the Scope entity.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Type ScopeType { get; set; } = typeof(OpenIddictScope);

        /// <summary>
        /// Gets or sets the type corresponding to the Token entity.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Type TokenType { get; set; } = typeof(OpenIddictToken);

        /// <summary>
        /// Gets the services collection.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IServiceCollection Services { get; }

        /// <summary>
        /// Adds a custom application manager.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddApplicationManager<TManager>() where TManager : class
            => AddApplicationManager(typeof(TManager));

        /// <summary>
        /// Adds a custom application manager.
        /// </summary>
        /// <param name="type">The type of the custom manager.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddApplicationManager([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(OpenIddictApplicationManager<>).MakeGenericType(ApplicationType);
            if (!contract.IsAssignableFrom(type))
            {
                throw new InvalidOperationException("Custom managers must be derived from OpenIddictApplicationManager.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom application store.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddApplicationStore<TStore>() where TStore : class
            => AddApplicationStore(typeof(TStore));

        /// <summary>
        /// Adds a custom application store.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddApplicationStore([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(IOpenIddictApplicationStore<>).MakeGenericType(ApplicationType);
            if (!contract.IsAssignableFrom(type))
            {
                throw new InvalidOperationException("Custom stores must implement IOpenIddictApplicationStore.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom authorization manager.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddAuthorizationManager<TManager>() where TManager : class
            => AddAuthorizationManager(typeof(TManager));

        /// <summary>
        /// Adds a custom authorization manager.
        /// </summary>
        /// <param name="type">The type of the custom manager.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddAuthorizationManager([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(OpenIddictAuthorizationManager<>).MakeGenericType(AuthorizationType);
            if (!contract.IsAssignableFrom(type))
            {
                throw new InvalidOperationException("Custom managers must be derived from OpenIddictAuthorizationManager.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom authorization store.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddAuthorizationStore<TStore>() where TStore : class
            => AddAuthorizationStore(typeof(TStore));

        /// <summary>
        /// Adds a custom authorization store.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddAuthorizationStore([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(IOpenIddictAuthorizationStore<>).MakeGenericType(AuthorizationType);
            if (!contract.IsAssignableFrom(type))
            {
                throw new InvalidOperationException("Custom stores must implement IOpenIddictAuthorizationStore.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom scope manager.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddScopeManager<TManager>() where TManager : class
            => AddScopeManager(typeof(TManager));

        /// <summary>
        /// Adds a custom scope manager.
        /// </summary>
        /// <param name="type">The type of the custom manager.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddScopeManager([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(OpenIddictScopeManager<>).MakeGenericType(ScopeType);
            if (!contract.IsAssignableFrom(type))
            {
                throw new InvalidOperationException("Custom managers must be derived from OpenIddictScopeManager.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom scope store.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddScopeStore<TStore>() where TStore : class
            => AddScopeStore(typeof(TStore));

        /// <summary>
        /// Adds a custom scope store.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddScopeStore([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(IOpenIddictScopeStore<>).MakeGenericType(ScopeType);
            if (!contract.IsAssignableFrom(type))
            {
                throw new InvalidOperationException("Custom stores must implement IOpenIddictScopeStore.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom token manager.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddTokenManager<TManager>() where TManager : class
            => AddTokenManager(typeof(TManager));

        /// <summary>
        /// Adds a custom token manager.
        /// </summary>
        /// <param name="type">The type of the custom manager.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddTokenManager([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(OpenIddictTokenManager<>).MakeGenericType(TokenType);
            if (!contract.IsAssignableFrom(type))
            {
                throw new InvalidOperationException("Custom managers must be derived from OpenIddictTokenManager.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom token store.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddTokenStore<TStore>() where TStore : class
            => AddTokenStore(typeof(TStore));

        /// <summary>
        /// Adds a custom token store.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddTokenStore([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(IOpenIddictTokenStore<>).MakeGenericType(TokenType);
            if (!contract.IsAssignableFrom(type))
            {
                throw new InvalidOperationException("Custom stores must implement IOpenIddictTokenStore.");
            }

            Services.AddScoped(contract, type);

            return this;
        }
    }
}