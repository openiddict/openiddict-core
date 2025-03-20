/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict Entity Framework Core services.
/// </summary>
public sealed class OpenIddictEntityFrameworkCoreBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictEntityFrameworkCoreBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictEntityFrameworkCoreBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict Entity Framework Core configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictEntityFrameworkCoreBuilder"/> instance.</returns>
    public OpenIddictEntityFrameworkCoreBuilder Configure(Action<OpenIddictEntityFrameworkCoreOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Prevents the Entity Framework Core stores from using bulk operations.
    /// </summary>
    /// <remarks>
    /// Note: bulk operations are only supported when targeting .NET 7.0 and higher.
    /// </remarks>
    /// <returns>The <see cref="OpenIddictEntityFrameworkCoreBuilder"/> instance.</returns>
    public OpenIddictEntityFrameworkCoreBuilder DisableBulkOperations()
        => Configure(options => options.DisableBulkOperations = true);

    /// <summary>
    /// Configures OpenIddict to use the default OpenIddict
    /// Entity Framework Core entities, with the specified key type.
    /// </summary>
    /// <returns>The <see cref="OpenIddictEntityFrameworkCoreBuilder"/> instance.</returns>
    public OpenIddictEntityFrameworkCoreBuilder ReplaceDefaultEntities<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey>()
        where TKey : notnull, IEquatable<TKey>
        => ReplaceDefaultEntities<OpenIddictEntityFrameworkCoreApplication<TKey>,
                                  OpenIddictEntityFrameworkCoreAuthorization<TKey>,
                                  OpenIddictEntityFrameworkCoreScope<TKey>,
                                  OpenIddictEntityFrameworkCoreToken<TKey>, TKey>();

    /// <summary>
    /// Configures OpenIddict to use the specified entities, derived
    /// from the default OpenIddict Entity Framework Core entities.
    /// </summary>
    /// <returns>The <see cref="OpenIddictEntityFrameworkCoreBuilder"/> instance.</returns>
    public OpenIddictEntityFrameworkCoreBuilder ReplaceDefaultEntities<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TScope,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey>()
        where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
        where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
        where TScope : OpenIddictEntityFrameworkCoreScope<TKey>
        where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
        where TKey : notnull, IEquatable<TKey>
    {
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictApplicationManager>(static provider =>
            provider.GetRequiredService<OpenIddictApplicationManager<TApplication>>()));
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictAuthorizationManager>(static provider =>
            provider.GetRequiredService<OpenIddictAuthorizationManager<TAuthorization>>()));
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictScopeManager>(static provider =>
            provider.GetRequiredService<OpenIddictScopeManager<TScope>>()));
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictTokenManager>(static provider =>
            provider.GetRequiredService<OpenIddictTokenManager<TToken>>()));

        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictApplicationStore<TApplication>,
            OpenIddictEntityFrameworkCoreApplicationStore<TApplication, TAuthorization, TToken, TKey>>());
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictAuthorizationStore<TAuthorization>,
            OpenIddictEntityFrameworkCoreAuthorizationStore<TAuthorization, TApplication, TToken, TKey>>());
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictScopeStore<TScope>,
            OpenIddictEntityFrameworkCoreScopeStore<TScope, TKey>>());
        Services.Replace(ServiceDescriptor.Scoped<IOpenIddictTokenStore<TToken>,
            OpenIddictEntityFrameworkCoreTokenStore<TToken, TApplication, TAuthorization, TKey>>());

        return this;
    }

    /// <summary>
    /// Configures the OpenIddict Entity Framework Core stores to use the specified database context type.
    /// </summary>
    /// <typeparam name="TContext">The type of the <see cref="DbContext"/> used by OpenIddict.</typeparam>
    /// <returns>The <see cref="OpenIddictEntityFrameworkCoreBuilder"/> instance.</returns>
    public OpenIddictEntityFrameworkCoreBuilder UseDbContext<TContext>() where TContext : DbContext
    {
        Services.Replace(ServiceDescriptor.Scoped<
            IOpenIddictEntityFrameworkCoreContext, OpenIddictEntityFrameworkCoreContext<TContext>>());

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
