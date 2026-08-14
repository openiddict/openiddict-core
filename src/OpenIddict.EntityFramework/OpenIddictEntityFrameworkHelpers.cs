/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFramework;
using OpenIddict.EntityFramework.Models;

namespace System.Data.Entity;

/// <summary>
/// Exposes extensions simplifying the integration between OpenIddict and Entity Framework 6.x.
/// </summary>
public static class OpenIddictEntityFrameworkHelpers
{
    /// <summary>
    /// Registers the OpenIddict entity sets in the Entity Framework 6.x context
    /// using the default OpenIddict models and the default key type (string).
    /// </summary>
    /// <param name="builder">The builder used to configure the Entity Framework context.</param>
    /// <returns>The Entity Framework context builder.</returns>
    public static DbModelBuilder UseOpenIddict(this DbModelBuilder builder)
        => builder.UseOpenIddict<OpenIddictEntityFrameworkApplication,
                                 OpenIddictEntityFrameworkAuthorization,
                                 OpenIddictEntityFrameworkResource,
                                 OpenIddictEntityFrameworkScope,
                                 OpenIddictEntityFrameworkSession,
                                 OpenIddictEntityFrameworkToken, string>();

    /// <summary>
    /// Registers the OpenIddict entity sets in the Entity Framework 6.x
    /// context using the specified entities and the specified key type.
    /// </summary>
    /// <remarks>
    /// Note: when using custom entities, the new entities MUST be registered by calling
    /// <see cref="OpenIddictEntityFrameworkBuilder.ReplaceDefaultEntities{TApplication, TAuthorization, TResource, TScope, TSession, TToken, TKey}"/>.
    /// </remarks>
    /// <param name="builder">The builder used to configure the Entity Framework context.</param>
    /// <returns>The Entity Framework context builder.</returns>
    public static DbModelBuilder UseOpenIddict<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TResource,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TScope,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TSession,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey>(this DbModelBuilder builder)
        where TApplication : OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TToken>
        where TAuthorization : OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TToken>
        where TResource : OpenIddictEntityFrameworkResource<TKey>
        where TScope : OpenIddictEntityFrameworkScope<TKey>
        where TSession : OpenIddictEntityFrameworkSession<TKey, TApplication, TAuthorization>
        where TToken : OpenIddictEntityFrameworkToken<TKey, TApplication, TAuthorization>
        where TKey : notnull, IEquatable<TKey>
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Configurations
            .Add(new OpenIddictEntityFrameworkApplicationConfiguration<TApplication, TAuthorization, TToken, TKey>())
            .Add(new OpenIddictEntityFrameworkAuthorizationConfiguration<TAuthorization, TApplication, TToken, TKey>())
            .Add(new OpenIddictEntityFrameworkResourceConfiguration<TResource, TKey>())
            .Add(new OpenIddictEntityFrameworkScopeConfiguration<TScope, TKey>())
            .Add(new OpenIddictEntityFrameworkSessionConfiguration<TSession, TApplication, TAuthorization, TToken, TKey>())
            .Add(new OpenIddictEntityFrameworkTokenConfiguration<TToken, TApplication, TAuthorization, TKey>());

        return builder;
    }
}
