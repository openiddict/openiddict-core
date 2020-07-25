/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.Extensions;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes the necessary methods required to configure the OpenIddict core services.
    /// </summary>
    public class OpenIddictCoreBuilder
    {
        /// <summary>
        /// Initializes a new instance of <see cref="OpenIddictCoreBuilder"/>.
        /// </summary>
        /// <param name="services">The services collection.</param>
        public OpenIddictCoreBuilder([NotNull] IServiceCollection services)
            => Services = services ?? throw new ArgumentNullException(nameof(services));

        /// <summary>
        /// Gets the services collection.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IServiceCollection Services { get; }

        /// <summary>
        /// Amends the default OpenIddict core configuration.
        /// </summary>
        /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder Configure([NotNull] Action<OpenIddictCoreOptions> configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            Services.Configure(configuration);

            return this;
        }

        /// <summary>
        /// Adds a custom application store by a custom implementation derived
        /// from <see cref="IOpenIddictApplicationStore{TApplication}"/>.
        /// Note: when using this overload, the application store
        /// must be either a non-generic or closed generic service.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder AddApplicationStore<TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
            where TStore : class
            => AddApplicationStore(typeof(TStore), lifetime);

        /// <summary>
        /// Adds a custom application store by a custom implementation derived
        /// from <see cref="IOpenIddictApplicationStore{TApplication}"/>.
        /// Note: when using this overload, the application store can be
        /// either a non-generic, a closed or an open generic service.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder AddApplicationStore(
            [NotNull] Type type, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var root = OpenIddictHelpers.FindGenericBaseType(type, typeof(IOpenIddictApplicationStore<>));
            if (root == null)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            // Note: managers can be either open generics (e.g OpenIddictApplicationStore<>)
            // or closed generics (e.g OpenIddictApplicationStore<OpenIddictApplication>).
            if (type.IsGenericTypeDefinition)
            {
                if (type.GetGenericArguments().Length != 1)
                {
                    throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
                }

                Services.Replace(new ServiceDescriptor(typeof(IOpenIddictApplicationStore<>), type, lifetime));
            }

            else
            {
                Services.Replace(new ServiceDescriptor(typeof(IOpenIddictApplicationStore<>)
                    .MakeGenericType(root.GenericTypeArguments[0]), type, lifetime));
            }

            return this;
        }

        /// <summary>
        /// Adds a custom authorization store by a custom implementation derived
        /// from <see cref="IOpenIddictAuthorizationStore{TAuthorization}"/>.
        /// Note: when using this overload, the authorization store
        /// must be either a non-generic or closed generic service.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder AddAuthorizationStore<TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
            where TStore : class
            => AddAuthorizationStore(typeof(TStore), lifetime);

        /// <summary>
        /// Adds a custom authorization store by a custom implementation derived
        /// from <see cref="IOpenIddictAuthorizationStore{TAuthorization}"/>.
        /// Note: when using this overload, the authorization store can be
        /// either a non-generic, a closed or an open generic service.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder AddAuthorizationStore(
            [NotNull] Type type, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var root = OpenIddictHelpers.FindGenericBaseType(type, typeof(IOpenIddictAuthorizationStore<>));
            if (root == null)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            // Note: managers can be either open generics (e.g OpenIddictAuthorizationStore<>)
            // or closed generics (e.g OpenIddictAuthorizationStore<OpenIddictAuthorization>).
            if (type.IsGenericTypeDefinition)
            {
                if (type.GetGenericArguments().Length != 1)
                {
                    throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
                }

                Services.Replace(new ServiceDescriptor(typeof(IOpenIddictAuthorizationStore<>), type, lifetime));
            }

            else
            {
                Services.Replace(new ServiceDescriptor(typeof(IOpenIddictAuthorizationStore<>)
                    .MakeGenericType(root.GenericTypeArguments[0]), type, lifetime));
            }

            return this;
        }

        /// <summary>
        /// Adds a custom scope store by a custom implementation derived
        /// from <see cref="IOpenIddictScopeStore{TScope}"/>.
        /// Note: when using this overload, the scope store
        /// must be either a non-generic or closed generic service.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder AddScopeStore<TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
            where TStore : class
            => AddScopeStore(typeof(TStore), lifetime);

        /// <summary>
        /// Adds a custom scope store by a custom implementation derived
        /// from <see cref="IOpenIddictScopeStore{TScope}"/>.
        /// Note: when using this overload, the scope store can be
        /// either a non-generic, a closed or an open generic service.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder AddScopeStore(
            [NotNull] Type type, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var root = OpenIddictHelpers.FindGenericBaseType(type, typeof(IOpenIddictScopeStore<>));
            if (root == null)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            // Note: managers can be either open generics (e.g OpenIddictScopeStore<>)
            // or closed generics (e.g OpenIddictScopeStore<OpenIddictScope>).
            if (type.IsGenericTypeDefinition)
            {
                if (type.GetGenericArguments().Length != 1)
                {
                    throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
                }

                Services.Replace(new ServiceDescriptor(typeof(IOpenIddictScopeStore<>), type, lifetime));
            }

            else
            {
                Services.Replace(new ServiceDescriptor(typeof(IOpenIddictScopeStore<>)
                    .MakeGenericType(root.GenericTypeArguments[0]), type, lifetime));
            }

            return this;
        }

        /// <summary>
        /// Adds a custom token store by a custom implementation derived
        /// from <see cref="IOpenIddictTokenStore{TToken}"/>.
        /// Note: when using this overload, the token store
        /// must be either a non-generic or closed generic service.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder AddTokenStore<TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
            where TStore : class
            => AddTokenStore(typeof(TStore), lifetime);

        /// <summary>
        /// Adds a custom token store by a custom implementation derived
        /// from <see cref="IOpenIddictTokenStore{TToken}"/>.
        /// Note: when using this overload, the token store can be
        /// either a non-generic, a closed or an open generic service.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder AddTokenStore(
            [NotNull] Type type, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var root = OpenIddictHelpers.FindGenericBaseType(type, typeof(IOpenIddictTokenStore<>));
            if (root == null)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            // Note: managers can be either open generics (e.g OpenIddictTokenStore<>)
            // or closed generics (e.g OpenIddictTokenStore<OpenIddictToken>).
            if (type.IsGenericTypeDefinition)
            {
                if (type.GetGenericArguments().Length != 1)
                {
                    throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
                }

                Services.Replace(new ServiceDescriptor(typeof(IOpenIddictTokenStore<>), type, lifetime));
            }

            else
            {
                Services.Replace(new ServiceDescriptor(typeof(IOpenIddictTokenStore<>)
                    .MakeGenericType(root.GenericTypeArguments[0]), type, lifetime));
            }

            return this;
        }

        /// <summary>
        /// Replace the default application manager by a custom manager derived
        /// from <see cref="OpenIddictApplicationManager{TApplication}"/>.
        /// Note: when using this overload, the application manager
        /// must be either a non-generic or closed generic service.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceApplicationManager<TManager>()
            where TManager : class
            => ReplaceApplicationManager(typeof(TManager));

        /// <summary>
        /// Replace the default application manager by a custom manager derived
        /// from <see cref="OpenIddictApplicationManager{TApplication}"/>.
        /// Note: when using this overload, the application manager can be
        /// either a non-generic, a closed or an open generic service.
        /// </summary>
        /// <param name="type">The type of the custom manager.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceApplicationManager([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var root = OpenIddictHelpers.FindGenericBaseType(type, typeof(OpenIddictApplicationManager<>));
            if (root == null)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            // Note: managers can be either open generics (e.g OpenIddictApplicationManager<>)
            // or closed generics (e.g OpenIddictApplicationManager<OpenIddictApplication>).
            if (type.IsGenericTypeDefinition)
            {
                if (type.GetGenericArguments().Length != 1)
                {
                    throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
                }

                Services.Replace(ServiceDescriptor.Scoped(type, type));
                Services.Replace(ServiceDescriptor.Scoped(typeof(OpenIddictApplicationManager<>), type));
            }

            else
            {
                object ResolveManager(IServiceProvider provider)
                    => provider.GetRequiredService(typeof(OpenIddictApplicationManager<>)
                        .MakeGenericType(root.GenericTypeArguments[0]));

                Services.Replace(ServiceDescriptor.Scoped(type, ResolveManager));
                Services.Replace(ServiceDescriptor.Scoped(typeof(OpenIddictApplicationManager<>)
                    .MakeGenericType(root.GenericTypeArguments[0]), type));
            }

            return this;
        }

        /// <summary>
        /// Replaces the default application store resolver by a custom implementation.
        /// </summary>
        /// <typeparam name="TResolver">The type of the custom store.</typeparam>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceApplicationStoreResolver<TResolver>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
            where TResolver : IOpenIddictApplicationStoreResolver
            => ReplaceApplicationStoreResolver(typeof(TResolver), lifetime);

        /// <summary>
        /// Replaces the default application store resolver by a custom implementation.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceApplicationStoreResolver(
            [NotNull] Type type, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (!typeof(IOpenIddictApplicationStoreResolver).IsAssignableFrom(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            Services.Replace(new ServiceDescriptor(typeof(IOpenIddictApplicationStoreResolver), type, lifetime));

            return this;
        }

        /// <summary>
        /// Replace the default authorization manager by a custom manager derived
        /// from <see cref="OpenIddictAuthorizationManager{TAuthorization}"/>.
        /// Note: when using this overload, the authorization manager
        /// must be either a non-generic or closed generic service.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceAuthorizationManager<TManager>()
            where TManager : class
            => ReplaceAuthorizationManager(typeof(TManager));

        /// <summary>
        /// Replace the default authorization manager by a custom manager derived
        /// from <see cref="OpenIddictAuthorizationManager{TAuthorization}"/>.
        /// Note: when using this overload, the authorization manager can be
        /// either a non-generic, a closed or an open generic service.
        /// </summary>
        /// <param name="type">The type of the custom manager.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceAuthorizationManager([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var root = OpenIddictHelpers.FindGenericBaseType(type, typeof(OpenIddictAuthorizationManager<>));
            if (root == null)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            // Note: managers can be either open generics (e.g OpenIddictAuthorizationManager<>)
            // or closed generics (e.g OpenIddictAuthorizationManager<OpenIddictAuthorization>).
            if (type.IsGenericTypeDefinition)
            {
                if (type.GetGenericArguments().Length != 1)
                {
                    throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
                }

                Services.Replace(ServiceDescriptor.Scoped(type, type));
                Services.Replace(ServiceDescriptor.Scoped(typeof(OpenIddictAuthorizationManager<>), type));
            }

            else
            {
                object ResolveManager(IServiceProvider provider)
                    => provider.GetRequiredService(typeof(OpenIddictAuthorizationManager<>)
                        .MakeGenericType(root.GenericTypeArguments[0]));

                Services.Replace(ServiceDescriptor.Scoped(type, ResolveManager));
                Services.Replace(ServiceDescriptor.Scoped(typeof(OpenIddictAuthorizationManager<>)
                    .MakeGenericType(root.GenericTypeArguments[0]), type));
            }

            return this;
        }

        /// <summary>
        /// Replaces the default authorization store resolver by a custom implementation.
        /// </summary>
        /// <typeparam name="TResolver">The type of the custom store.</typeparam>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceAuthorizationStoreResolver<TResolver>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
            where TResolver : IOpenIddictAuthorizationStoreResolver
            => ReplaceAuthorizationStoreResolver(typeof(TResolver), lifetime);

        /// <summary>
        /// Replaces the default authorization store resolver by a custom implementation.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceAuthorizationStoreResolver(
            [NotNull] Type type, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (!typeof(IOpenIddictAuthorizationStoreResolver).IsAssignableFrom(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            Services.Replace(new ServiceDescriptor(typeof(IOpenIddictAuthorizationStoreResolver), type, lifetime));

            return this;
        }

        /// <summary>
        /// Replace the default scope manager by a custom manager
        /// derived from <see cref="OpenIddictScopeManager{TScope}"/>.
        /// Note: when using this overload, the scope manager
        /// must be either a non-generic or closed generic service.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceScopeManager<TManager>()
            where TManager : class
            => ReplaceScopeManager(typeof(TManager));

        /// <summary>
        /// Replace the default scope manager by a custom manager
        /// derived from <see cref="OpenIddictScopeManager{TScope}"/>.
        /// Note: when using this overload, the scope manager can be
        /// either a non-generic, a closed or an open generic service.
        /// </summary>
        /// <param name="type">The type of the custom manager.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceScopeManager([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var root = OpenIddictHelpers.FindGenericBaseType(type, typeof(OpenIddictScopeManager<>));
            if (root == null)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            // Note: managers can be either open generics (e.g OpenIddictScopeManager<>)
            // or closed generics (e.g OpenIddictScopeManager<OpenIddictScope>).
            if (type.IsGenericTypeDefinition)
            {
                if (type.GetGenericArguments().Length != 1)
                {
                    throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
                }

                Services.Replace(ServiceDescriptor.Scoped(type, type));
                Services.Replace(ServiceDescriptor.Scoped(typeof(OpenIddictScopeManager<>), type));
            }

            else
            {
                object ResolveManager(IServiceProvider provider)
                    => provider.GetRequiredService(typeof(OpenIddictScopeManager<>)
                        .MakeGenericType(root.GenericTypeArguments[0]));

                Services.Replace(ServiceDescriptor.Scoped(type, ResolveManager));
                Services.Replace(ServiceDescriptor.Scoped(typeof(OpenIddictScopeManager<>)
                    .MakeGenericType(root.GenericTypeArguments[0]), type));
            }

            return this;
        }

        /// <summary>
        /// Replaces the default scope store resolver by a custom implementation.
        /// </summary>
        /// <typeparam name="TResolver">The type of the custom store.</typeparam>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceScopeStoreResolver<TResolver>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
            where TResolver : IOpenIddictScopeStoreResolver
            => ReplaceScopeStoreResolver(typeof(TResolver), lifetime);

        /// <summary>
        /// Replaces the default scope store resolver by a custom implementation.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceScopeStoreResolver(
            [NotNull] Type type, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (!typeof(IOpenIddictScopeStoreResolver).IsAssignableFrom(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            Services.Replace(new ServiceDescriptor(typeof(IOpenIddictScopeStoreResolver), type, lifetime));

            return this;
        }

        /// <summary>
        /// Replace the default token manager by a custom manager
        /// derived from <see cref="OpenIddictTokenManager{TToken}"/>.
        /// Note: when using this overload, the token manager
        /// must be either a non-generic or closed generic service.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceTokenManager<TManager>()
            where TManager : class
            => ReplaceTokenManager(typeof(TManager));

        /// <summary>
        /// Replace the default token manager by a custom manager
        /// derived from <see cref="OpenIddictTokenManager{TToken}"/>.
        /// Note: when using this overload, the token manager can be
        /// either a non-generic, a closed or an open generic service.
        /// </summary>
        /// <param name="type">The type of the custom manager.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceTokenManager([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            var root = OpenIddictHelpers.FindGenericBaseType(type, typeof(OpenIddictTokenManager<>));
            if (root == null)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            // Note: managers can be either open generics (e.g OpenIddictTokenManager<>)
            // or closed generics (e.g OpenIddictTokenManager<OpenIddictToken>).
            if (type.IsGenericTypeDefinition)
            {
                if (type.GetGenericArguments().Length != 1)
                {
                    throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
                }

                Services.Replace(ServiceDescriptor.Scoped(type, type));
                Services.Replace(ServiceDescriptor.Scoped(typeof(OpenIddictTokenManager<>), type));
            }

            else
            {
                object ResolveManager(IServiceProvider provider)
                    => provider.GetRequiredService(typeof(OpenIddictTokenManager<>)
                        .MakeGenericType(root.GenericTypeArguments[0]));

                Services.Replace(ServiceDescriptor.Scoped(type, ResolveManager));
                Services.Replace(ServiceDescriptor.Scoped(typeof(OpenIddictTokenManager<>)
                    .MakeGenericType(root.GenericTypeArguments[0]), type));
            }

            return this;
        }

        /// <summary>
        /// Replaces the default token store resolver by a custom implementation.
        /// </summary>
        /// <typeparam name="TResolver">The type of the custom store.</typeparam>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceTokenStoreResolver<TResolver>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
            where TResolver : IOpenIddictTokenStoreResolver
            => ReplaceTokenStoreResolver(typeof(TResolver), lifetime);

        /// <summary>
        /// Replaces the default token store resolver by a custom implementation.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder ReplaceTokenStoreResolver(
            [NotNull] Type type, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (!typeof(IOpenIddictTokenStoreResolver).IsAssignableFrom(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            Services.Replace(new ServiceDescriptor(typeof(IOpenIddictTokenStoreResolver), type, lifetime));

            return this;
        }

        /// <summary>
        /// Disables additional filtering so that the OpenIddict managers don't execute a second check
        /// to ensure the results returned by the stores exactly match the specified query filters,
        /// casing included. Additional filtering shouldn't be disabled except when the underlying
        /// stores are guaranteed to execute case-sensitive filtering at the database level.
        /// Disabling this feature MAY result in security vulnerabilities in the other cases.
        /// </summary>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder DisableAdditionalFiltering()
            => Configure(options => options.DisableAdditionalFiltering = true);

        /// <summary>
        /// Disables the scoped entity caching applied by the OpenIddict managers.
        /// Disabling entity caching may have a noticeable impact on the performance
        /// of your application and result in multiple queries being sent by the stores.
        /// </summary>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder DisableEntityCaching()
            => Configure(options => options.DisableEntityCaching = true);

        /// <summary>
        /// Configures OpenIddict to use the specified entity as the default application entity.
        /// </summary>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder SetDefaultApplicationEntity<TApplication>() where TApplication : class
            => SetDefaultApplicationEntity(typeof(TApplication));

        /// <summary>
        /// Configures OpenIddict to use the specified entity as the default application entity.
        /// </summary>
        /// <param name="type">The application entity type.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder SetDefaultApplicationEntity([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (type.IsValueType)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            return Configure(options => options.DefaultApplicationType = type);
        }

        /// <summary>
        /// Configures OpenIddict to use the specified entity as the default authorization entity.
        /// </summary>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder SetDefaultAuthorizationEntity<TAuthorization>() where TAuthorization : class
            => SetDefaultAuthorizationEntity(typeof(TAuthorization));

        /// <summary>
        /// Configures OpenIddict to use the specified entity as the default authorization entity.
        /// </summary>
        /// <param name="type">The authorization entity type.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder SetDefaultAuthorizationEntity([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (type.IsValueType)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            return Configure(options => options.DefaultAuthorizationType = type);
        }

        /// <summary>
        /// Configures OpenIddict to use the specified entity as the default scope entity.
        /// </summary>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder SetDefaultScopeEntity<TScope>() where TScope : class
            => SetDefaultScopeEntity(typeof(TScope));

        /// <summary>
        /// Configures OpenIddict to use the specified entity as the default scope entity.
        /// </summary>
        /// <param name="type">The scope entity type.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder SetDefaultScopeEntity([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (type.IsValueType)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            return Configure(options => options.DefaultScopeType = type);
        }

        /// <summary>
        /// Configures OpenIddict to use the specified entity as the default token entity.
        /// </summary>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder SetDefaultTokenEntity<TToken>() where TToken : class
            => SetDefaultTokenEntity(typeof(TToken));

        /// <summary>
        /// Configures OpenIddict to use the specified entity as the default token entity.
        /// </summary>
        /// <param name="type">The token entity type.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder SetDefaultTokenEntity([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (type.IsValueType)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1231), nameof(type));
            }

            return Configure(options => options.DefaultTokenType = type);
        }

        /// <summary>
        /// Configures OpenIddict to use the specified entity cache limit,
        /// after which the internal cache is automatically compacted.
        /// </summary>
        /// <param name="limit">The cache limit, in number of entries.</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public OpenIddictCoreBuilder SetEntityCacheLimit(int limit)
        {
            if (limit < 10)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1232), nameof(limit));
            }

            return Configure(options => options.EntityCacheLimit = limit);
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="obj">The object to compare with the current object.</param>
        /// <returns><c>true</c> if the specified object is equal to the current object; otherwise, false.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([CanBeNull] object obj) => base.Equals(obj);

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
        public override string ToString() => base.ToString();
    }
}
