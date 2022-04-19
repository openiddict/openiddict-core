/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIddict.EntityFrameworkCore;

/// <summary>
/// Represents a model customizer able to register the entity sets
/// required by the OpenIddict stack in an Entity Framework Core context.
/// </summary>
public class OpenIddictEntityFrameworkCoreCustomizer<TApplication, TAuthorization, TScope, TToken, TKey> : RelationalModelCustomizer
    where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
    where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
    where TScope : OpenIddictEntityFrameworkCoreScope<TKey>
    where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreCustomizer(ModelCustomizerDependencies dependencies)
        : base(dependencies)
    {
    }

    /// <inheritdoc/>
    public override void Customize(ModelBuilder modelBuilder, DbContext context)
    {
        if (modelBuilder is null)
        {
            throw new ArgumentNullException(nameof(modelBuilder));
        }

        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        // Register the OpenIddict entity sets.
        modelBuilder.UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>();

        base.Customize(modelBuilder, context);
    }
}
