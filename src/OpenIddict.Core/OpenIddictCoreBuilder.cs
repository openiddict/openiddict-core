/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Core;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict core services.
/// </summary>
public sealed class OpenIddictCoreBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictCoreBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictCoreBuilder(IServiceCollection services)
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
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder Configure(Action<OpenIddictCoreOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Replaces the application manager by the specified type.
    /// </summary>
    /// <typeparam name="TApplication">The type of the entity.</typeparam>
    /// <typeparam name="TManager">The type of the manager.</typeparam>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceApplicationManager<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TManager>()
        where TApplication : class
        where TManager : OpenIddictApplicationManager<TApplication>
    {
        Services.Replace(ServiceDescriptor.Scoped<OpenIddictApplicationManager<TApplication>, TManager>());

        return this;
    }

    /// <summary>
    /// Replaces the application manager by the specified type.
    /// </summary>
    /// <remarks>
    /// Note: the specified type MUST be an open generic type definition containing exactly one generic argument.
    /// </remarks>
    /// <param name="type">The type of the manager.</param>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceApplicationManager(
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type type)
    {
        if (!type.IsGenericTypeDefinition || type.GetGenericArguments() is not { Length: 1 })
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0232), nameof(type));
        }

        Services.Replace(ServiceDescriptor.Scoped(typeof(OpenIddictApplicationManager<>), type));

        return this;
    }

    /// <summary>
    /// Replaces the application store by the specified type.
    /// </summary>
    /// <typeparam name="TApplication">The type of the entity.</typeparam>
    /// <typeparam name="TStore">The type of the store.</typeparam>
    /// <param name="lifetime">The lifetime of the store.</param>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceApplicationStore<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore>(
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TApplication : class
        where TStore : IOpenIddictApplicationStore<TApplication>
    {
        Services.Replace(ServiceDescriptor.Describe(typeof(IOpenIddictApplicationStore<TApplication>), typeof(TStore), lifetime));

        return this;
    }

    /// <summary>
    /// Replaces the application store by the specified type.
    /// </summary>
    /// <remarks>
    /// Note: the specified type MUST be an open generic type definition containing exactly one generic argument.
    /// </remarks>
    /// <param name="type">The type of the store.</param>
    /// <param name="lifetime">The lifetime of the store.</param>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceApplicationStore(
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type type,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
    {
        if (!type.IsGenericTypeDefinition || type.GetGenericArguments() is not { Length: 1 })
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0232), nameof(type));
        }

        Services.Replace(ServiceDescriptor.Describe(typeof(IOpenIddictApplicationStore<>), type, lifetime));

        return this;
    }

    /// <summary>
    /// Replaces the authorization manager by the specified type.
    /// </summary>
    /// <typeparam name="TAuthorization">The type of the entity.</typeparam>
    /// <typeparam name="TManager">The type of the manager.</typeparam>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceAuthorizationManager<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TManager>()
        where TAuthorization : class
        where TManager : OpenIddictAuthorizationManager<TAuthorization>
    {
        Services.Replace(ServiceDescriptor.Scoped<OpenIddictAuthorizationManager<TAuthorization>, TManager>());

        return this;
    }

    /// <summary>
    /// Replaces the authorization manager by the specified type.
    /// </summary>
    /// <remarks>
    /// Note: the specified type MUST be an open generic type definition containing exactly one generic argument.
    /// </remarks>
    /// <param name="type">The type of the manager.</param>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceAuthorizationManager(
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type type)
    {
        if (!type.IsGenericTypeDefinition || type.GetGenericArguments() is not { Length: 1 })
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0232), nameof(type));
        }

        Services.Replace(ServiceDescriptor.Scoped(typeof(OpenIddictAuthorizationManager<>), type));

        return this;
    }

    /// <summary>
    /// Replaces the authorization store by the specified type.
    /// </summary>
    /// <typeparam name="TAuthorization">The type of the entity.</typeparam>
    /// <typeparam name="TStore">The type of the store.</typeparam>
    /// <param name="lifetime">The lifetime of the store.</param>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceAuthorizationStore<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore>(
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TAuthorization : class
        where TStore : IOpenIddictAuthorizationStore<TAuthorization>
    {
        Services.Replace(ServiceDescriptor.Describe(typeof(IOpenIddictAuthorizationStore<TAuthorization>), typeof(TStore), lifetime));

        return this;
    }

    /// <summary>
    /// Replaces the authorization store by the specified type.
    /// </summary>
    /// <remarks>
    /// Note: the specified type MUST be an open generic type definition containing exactly one generic argument.
    /// </remarks>
    /// <param name="type">The type of the store.</param>
    /// <param name="lifetime">The lifetime of the store.</param>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceAuthorizationStore(
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type type,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
    {
        if (!type.IsGenericTypeDefinition || type.GetGenericArguments() is not { Length: 1 })
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0232), nameof(type));
        }

        Services.Replace(ServiceDescriptor.Describe(typeof(IOpenIddictAuthorizationStore<>), type, lifetime));

        return this;
    }

    /// <summary>
    /// Replaces the scope manager by the specified type.
    /// </summary>
    /// <typeparam name="TScope">The type of the entity.</typeparam>
    /// <typeparam name="TManager">The type of the manager.</typeparam>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceScopeManager<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TScope,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TManager>()
        where TScope : class
        where TManager : OpenIddictScopeManager<TScope>
    {
        Services.Replace(ServiceDescriptor.Scoped<OpenIddictScopeManager<TScope>, TManager>());

        return this;
    }

    /// <summary>
    /// Replaces the scope manager by the specified type.
    /// </summary>
    /// <remarks>
    /// Note: the specified type MUST be an open generic type definition containing exactly one generic argument.
    /// </remarks>
    /// <param name="type">The type of the manager.</param>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceScopeManager(
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type type)
    {
        if (!type.IsGenericTypeDefinition || type.GetGenericArguments() is not { Length: 1 })
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0232), nameof(type));
        }

        Services.Replace(ServiceDescriptor.Scoped(typeof(OpenIddictScopeManager<>), type));

        return this;
    }

    /// <summary>
    /// Replaces the scope store by the specified type.
    /// </summary>
    /// <typeparam name="TScope">The type of the entity.</typeparam>
    /// <typeparam name="TStore">The type of the store.</typeparam>
    /// <param name="lifetime">The lifetime of the store.</param>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceScopeStore<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TScope,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore>(
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TScope : class
        where TStore : IOpenIddictScopeStore<TScope>
    {
        Services.Replace(ServiceDescriptor.Describe(typeof(IOpenIddictScopeStore<TScope>), typeof(TStore), lifetime));

        return this;
    }

    /// <summary>
    /// Replaces the scope store by the specified type.
    /// </summary>
    /// <remarks>
    /// Note: the specified type MUST be an open generic type definition containing exactly one generic argument.
    /// </remarks>
    /// <param name="type">The type of the store.</param>
    /// <param name="lifetime">The lifetime of the store.</param>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceScopeStore(
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type type,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
    {
        if (!type.IsGenericTypeDefinition || type.GetGenericArguments() is not { Length: 1 })
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0232), nameof(type));
        }

        Services.Replace(ServiceDescriptor.Describe(typeof(IOpenIddictScopeStore<>), type, lifetime));

        return this;
    }

    /// <summary>
    /// Replaces the token manager by the specified type.
    /// </summary>
    /// <typeparam name="TToken">The type of the entity.</typeparam>
    /// <typeparam name="TManager">The type of the manager.</typeparam>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceTokenManager<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TManager>()
        where TToken : class
        where TManager : OpenIddictTokenManager<TToken>
    {
        Services.Replace(ServiceDescriptor.Scoped<OpenIddictTokenManager<TToken>, TManager>());

        return this;
    }

    /// <summary>
    /// Replaces the token manager by the specified type.
    /// </summary>
    /// <remarks>
    /// Note: the specified type MUST be an open generic type definition containing exactly one generic argument.
    /// </remarks>
    /// <param name="type">The type of the manager.</param>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceTokenManager(
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type type)
    {
        if (!type.IsGenericTypeDefinition || type.GetGenericArguments() is not { Length: 1 })
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0232), nameof(type));
        }

        Services.Replace(ServiceDescriptor.Scoped(typeof(OpenIddictTokenManager<>), type));

        return this;
    }

    /// <summary>
    /// Replaces the token store by the specified type.
    /// </summary>
    /// <typeparam name="TToken">The type of the entity.</typeparam>
    /// <typeparam name="TStore">The type of the store.</typeparam>
    /// <param name="lifetime">The lifetime of the store.</param>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceTokenStore<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore>(
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TToken : class
        where TStore : IOpenIddictTokenStore<TToken>
    {
        Services.Replace(ServiceDescriptor.Describe(typeof(IOpenIddictTokenStore<TToken>), typeof(TStore), lifetime));

        return this;
    }

    /// <summary>
    /// Replaces the token store by the specified type.
    /// </summary>
    /// <remarks>
    /// Note: the specified type MUST be an open generic type definition containing exactly one generic argument.
    /// </remarks>
    /// <param name="type">The type of the store.</param>
    /// <param name="lifetime">The lifetime of the store.</param>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder ReplaceTokenStore(
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type type,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
    {
        if (!type.IsGenericTypeDefinition || type.GetGenericArguments() is not { Length: 1 })
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0232), nameof(type));
        }

        Services.Replace(ServiceDescriptor.Describe(typeof(IOpenIddictTokenStore<>), type, lifetime));

        return this;
    }

    /// <summary>
    /// Disables additional filtering so that the OpenIddict managers don't execute a second check
    /// to ensure the results returned by the stores exactly match the specified query filters,
    /// casing included. Additional filtering shouldn't be disabled except when the underlying
    /// stores are guaranteed to execute case-sensitive filtering at the database level.
    /// Disabling this feature MAY result in security vulnerabilities in the other cases.
    /// </summary>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder DisableAdditionalFiltering()
        => Configure(options => options.DisableAdditionalFiltering = true);

    /// <summary>
    /// Disables the scoped entity caching applied by the OpenIddict managers.
    /// Disabling entity caching may have a noticeable impact on the performance
    /// of your application and result in multiple queries being sent by the stores.
    /// </summary>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder DisableEntityCaching()
        => Configure(options => options.DisableEntityCaching = true);

    /// <summary>
    /// Configures OpenIddict to use the specified entity as the default application entity.
    /// </summary>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder SetDefaultApplicationEntity<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication>() where TApplication : class
    {
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictApplicationManager>(static provider =>
            provider.GetRequiredService<OpenIddictApplicationManager<TApplication>>()));

        return this;
    }

    /// <summary>
    /// Configures OpenIddict to use the specified entity as the default authorization entity.
    /// </summary>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder SetDefaultAuthorizationEntity<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization>() where TAuthorization : class
    {
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictAuthorizationManager>(static provider =>
            provider.GetRequiredService<OpenIddictAuthorizationManager<TAuthorization>>()));

        return this;
    }

    /// <summary>
    /// Configures OpenIddict to use the specified entity as the default scope entity.
    /// </summary>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder SetDefaultScopeEntity<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TScope>() where TScope : class
    {
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictScopeManager>(static provider =>
            provider.GetRequiredService<OpenIddictScopeManager<TScope>>()));

        return this;
    }

    /// <summary>
    /// Configures OpenIddict to use the specified entity as the default token entity.
    /// </summary>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder SetDefaultTokenEntity<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken>() where TToken : class
    {
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictTokenManager>(static provider =>
            provider.GetRequiredService<OpenIddictTokenManager<TToken>>()));

        return this;
    }

    /// <summary>
    /// Configures OpenIddict to use the specified entity cache limit,
    /// after which the internal cache is automatically compacted.
    /// </summary>
    /// <param name="limit">The cache limit, in number of entries.</param>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public OpenIddictCoreBuilder SetEntityCacheLimit(int limit)
    {
        if (limit < 10)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0233), nameof(limit));
        }

        return Configure(options => options.EntityCacheLimit = limit);
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => base.Equals(obj);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}
