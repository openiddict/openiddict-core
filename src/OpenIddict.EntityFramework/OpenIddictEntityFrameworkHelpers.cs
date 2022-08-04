/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Data.Entity.Infrastructure;
using System.Runtime.CompilerServices;
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
                                 OpenIddictEntityFrameworkScope,
                                 OpenIddictEntityFrameworkToken, string>();

    /// <summary>
    /// Registers the OpenIddict entity sets in the Entity Framework 6.x
    /// context using the specified entities and the specified key type.
    /// </summary>
    /// <remarks>
    /// Note: when using custom entities, the new entities MUST be registered by calling
    /// <see cref="OpenIddictEntityFrameworkBuilder.ReplaceDefaultEntities{TApplication, TAuthorization, TScope, TToken, TKey}"/>.
    /// </remarks>
    /// <param name="builder">The builder used to configure the Entity Framework context.</param>
    /// <returns>The Entity Framework context builder.</returns>
    public static DbModelBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>(this DbModelBuilder builder)
        where TApplication : OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TToken>
        where TAuthorization : OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TToken>
        where TScope : OpenIddictEntityFrameworkScope<TKey>
        where TToken : OpenIddictEntityFrameworkToken<TKey, TApplication, TAuthorization>
        where TKey : notnull, IEquatable<TKey>
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        builder.Configurations
            .Add(new OpenIddictEntityFrameworkApplicationConfiguration<TApplication, TAuthorization, TToken, TKey>())
            .Add(new OpenIddictEntityFrameworkAuthorizationConfiguration<TAuthorization, TApplication, TToken, TKey>())
            .Add(new OpenIddictEntityFrameworkScopeConfiguration<TScope, TKey>())
            .Add(new OpenIddictEntityFrameworkTokenConfiguration<TToken, TApplication, TAuthorization, TKey>());

        return builder;
    }

    /// <summary>
    /// Executes the query and returns the results as a streamed async enumeration.
    /// </summary>
    /// <typeparam name="T">The type of the returned entities.</typeparam>
    /// <param name="source">The query source.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The streamed async enumeration containing the results.</returns>
    internal static IAsyncEnumerable<T> AsAsyncEnumerable<T>(this IQueryable<T> source, CancellationToken cancellationToken)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        return ExecuteAsync(source, cancellationToken);

        static async IAsyncEnumerable<T> ExecuteAsync(IQueryable<T> source, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            using var enumerator = ((IDbAsyncEnumerable<T>)source).GetAsyncEnumerator();

            while (await enumerator.MoveNextAsync(cancellationToken))
            {
                yield return enumerator.Current;
            }
        }
    }
}
