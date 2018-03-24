/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using JetBrains.Annotations;
using OpenIddict.Core;

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
        public Type ApplicationType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the Authorization entity.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Type AuthorizationType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the Scope entity.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Type ScopeType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the Token entity.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Type TokenType { get; set; }

        /// <summary>
        /// Gets the services collection.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IServiceCollection Services { get; }

        /// <summary>
        /// Adds a custom application manager derived from
        /// <see cref="OpenIddictApplicationManager{TApplication}"/>.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddApplicationManager<TManager>() where TManager : class
            => AddApplicationManager(typeof(TManager));

        /// <summary>
        /// Adds a custom application manager derived from
        /// <see cref="OpenIddictApplicationManager{TApplication}"/>.
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
                throw new InvalidOperationException("The specified type is invalid.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom application store derived from
        /// <see cref="IOpenIddictApplicationStore{TApplication}"/>.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddApplicationStore<TStore>() where TStore : class
            => AddApplicationStore(typeof(TStore));

        /// <summary>
        /// Adds a custom application store derived from
        /// <see cref="IOpenIddictApplicationStore{TApplication}"/>.
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
                throw new InvalidOperationException("The specified type is invalid.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom authorization manager derived from
        /// <see cref="OpenIddictAuthorizationManager{TAuthorization}"/>.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddAuthorizationManager<TManager>() where TManager : class
            => AddAuthorizationManager(typeof(TManager));

        /// <summary>
        /// Adds a custom authorization manager derived from
        /// <see cref="OpenIddictAuthorizationManager{TAuthorization}"/>.
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
                throw new InvalidOperationException("The specified type is invalid.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom authorization store derived from
        /// <see cref="IOpenIddictAuthorizationStore{TAuthorization}"/>.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddAuthorizationStore<TStore>() where TStore : class
            => AddAuthorizationStore(typeof(TStore));

        /// <summary>
        /// Adds a custom authorization store derived from
        /// <see cref="IOpenIddictAuthorizationStore{TAuthorization}"/>.
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
                throw new InvalidOperationException("The specified type is invalid.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom scope manager derived from
        /// <see cref="OpenIddictScopeManager{TScope}"/>.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddScopeManager<TManager>() where TManager : class
            => AddScopeManager(typeof(TManager));

        /// <summary>
        /// Adds a custom scope manager derived from
        /// <see cref="OpenIddictScopeManager{TScope}"/>.
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
                throw new InvalidOperationException("The specified type is invalid.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom scope store derived from
        /// <see cref="IOpenIddictScopeStore{TScope}"/>.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddScopeStore<TStore>() where TStore : class
            => AddScopeStore(typeof(TStore));

        /// <summary>
        /// Adds a custom scope store derived from
        /// <see cref="IOpenIddictScopeStore{TScope}"/>.
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
                throw new InvalidOperationException("The specified type is invalid.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom token manager derived from
        /// <see cref="OpenIddictTokenManager{TToken}"/>.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddTokenManager<TManager>() where TManager : class
            => AddTokenManager(typeof(TManager));

        /// <summary>
        /// Adds a custom token manager derived from
        /// <see cref="OpenIddictTokenManager{TToken}"/>.
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
                throw new InvalidOperationException("The specified type is invalid.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom token store derived from
        /// <see cref="IOpenIddictTokenStore{TToken}"/>.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddTokenStore<TStore>() where TStore : class
            => AddTokenStore(typeof(TStore));

        /// <summary>
        /// Adds a custom token store derived from
        /// <see cref="IOpenIddictTokenStore{TToken}"/>.
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
                throw new InvalidOperationException("The specified type is invalid.");
            }

            Services.AddScoped(contract, type);

            return this;
        }
    }
}