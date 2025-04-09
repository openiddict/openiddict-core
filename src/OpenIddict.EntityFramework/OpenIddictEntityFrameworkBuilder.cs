/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Core;
using OpenIddict.EntityFramework;
using OpenIddict.EntityFramework.Models;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict Entity Framework 6.x services.
/// </summary>
public sealed class OpenIddictEntityFrameworkBuilder
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
    /// <returns>The <see cref="OpenIddictEntityFrameworkBuilder"/> instance.</returns>
    public OpenIddictEntityFrameworkBuilder Configure(Action<OpenIddictEntityFrameworkOptions> configuration)
    {
        if (configuration is null)
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
    /// <returns>The <see cref="OpenIddictEntityFrameworkBuilder"/> instance.</returns>
    public OpenIddictEntityFrameworkBuilder ReplaceDefaultEntities<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TScope,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey>()
        where TApplication : OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TToken>
        where TAuthorization : OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TToken>
        where TScope : OpenIddictEntityFrameworkScope<TKey>
        where TToken : OpenIddictEntityFrameworkToken<TKey, TApplication, TAuthorization>
        where TKey : notnull, IEquatable<TKey>
    {
        // Note: unlike Entity Framework Core, Entity Framework 6.x always
        // throws an exception when using generic types as entity types.
        //
        // To ensure a better exception is thrown, a manual check is made here.
        if (typeof(TApplication).IsGenericType || typeof(TAuthorization).IsGenericType ||
            typeof(TScope).IsGenericType || typeof(TToken).IsGenericType)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0277));
        }

#if SUPPORTS_TYPE_DESCRIPTOR_TYPE_REGISTRATION
        // If the specified key type isn't a string (which is special-cased by the stores to avoid having to resolve
        // a TypeDescriptor instance) and the platform supports type registration, register the key type to ensure the
        // TypeDescriptor associated with that type will be preserved by the IL Linker and can be resolved at runtime.
        if (typeof(TKey) != typeof(string))
        {
            TypeDescriptor.RegisterType<TKey>();
        }
#endif
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictApplicationManager>(static provider =>
            provider.GetRequiredService<OpenIddictApplicationManager<TApplication>>()));
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictAuthorizationManager>(static provider =>
            provider.GetRequiredService<OpenIddictAuthorizationManager<TAuthorization>>()));
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictScopeManager>(static provider =>
            provider.GetRequiredService<OpenIddictScopeManager<TScope>>()));
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictTokenManager>(static provider =>
            provider.GetRequiredService<OpenIddictTokenManager<TToken>>()));

        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictApplicationStore<TApplication>,
            OpenIddictEntityFrameworkApplicationStore<TApplication, TAuthorization, TToken, TKey>>());
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictAuthorizationStore<TAuthorization>,
            OpenIddictEntityFrameworkAuthorizationStore<TAuthorization, TApplication, TToken, TKey>>());
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictScopeStore<TScope>,
            OpenIddictEntityFrameworkScopeStore<TScope, TKey>>());
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictTokenStore<TToken>,
            OpenIddictEntityFrameworkTokenStore<TToken, TApplication, TAuthorization, TKey>>());

        return this;
    }

    /// <summary>
    /// Configures the OpenIddict Entity Framework 6.x stores to use the specified database context type.
    /// </summary>
    /// <typeparam name="TContext">The type of the <see cref="DbContext"/> used by OpenIddict.</typeparam>
    /// <returns>The <see cref="OpenIddictEntityFrameworkBuilder"/> instance.</returns>
    public OpenIddictEntityFrameworkBuilder UseDbContext<TContext>() where TContext : DbContext
    {
        Services.Replace(ServiceDescriptor.Scoped<
            IOpenIddictEntityFrameworkContext, OpenIddictEntityFrameworkContext<TContext>>());

        return this;
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
