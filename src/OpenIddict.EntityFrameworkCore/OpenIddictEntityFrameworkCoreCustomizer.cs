/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIddict.EntityFrameworkCore;

/// <summary>
/// Represents a model customizer able to register the entity sets
/// required by the OpenIddict stack in an Entity Framework Core context.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkCoreCustomizer<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TResource,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TScope,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TSession,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : RelationalModelCustomizer
    where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TSession, TToken>
    where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TSession, TToken>
    where TResource : OpenIddictEntityFrameworkCoreResource<TKey>
    where TScope : OpenIddictEntityFrameworkCoreScope<TKey>
    where TSession : OpenIddictEntityFrameworkCoreSession<TKey, TApplication, TAuthorization, TToken>
    where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization, TSession>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreCustomizer(ModelCustomizerDependencies dependencies)
        : base(dependencies)
    {
    }

    /// <inheritdoc/>
    public override void Customize(ModelBuilder modelBuilder, DbContext context)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        ArgumentNullException.ThrowIfNull(context);

        // Register the OpenIddict entity sets.
        modelBuilder.UseOpenIddict<TApplication, TAuthorization, TResource, TScope, TSession, TToken, TKey>();

        base.Customize(modelBuilder, context);
    }
}
