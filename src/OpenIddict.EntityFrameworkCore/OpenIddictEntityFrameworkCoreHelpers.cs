/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Data;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Extensions;

namespace Microsoft.EntityFrameworkCore;

/// <summary>
/// Exposes extensions simplifying the integration between OpenIddict and Entity Framework Core.
/// </summary>
public static class OpenIddictEntityFrameworkCoreHelpers
{
    /// <summary>
    /// Registers the OpenIddict entity sets in the Entity Framework Core context
    /// using the default OpenIddict models and the default key type (string).
    /// </summary>
    /// <param name="builder">The builder used to configure the Entity Framework context.</param>
    /// <returns>The Entity Framework context builder.</returns>
    public static DbContextOptionsBuilder UseOpenIddict(this DbContextOptionsBuilder builder)
        => builder.UseOpenIddict<OpenIddictEntityFrameworkCoreApplication,
                                 OpenIddictEntityFrameworkCoreAuthorization,
                                 OpenIddictEntityFrameworkCoreScope,
                                 OpenIddictEntityFrameworkCoreToken, string>();

    /// <summary>
    /// Registers the OpenIddict entity sets in the Entity Framework Core context
    /// using the default OpenIddict models and the default key type (string).
    /// </summary>
    /// <param name="builder">The builder used to configure the Entity Framework context.</param>
    /// <returns>The Entity Framework context builder.</returns>
    public static DbContextOptionsBuilder<TContext> UseOpenIddict<TContext>(this DbContextOptionsBuilder<TContext> builder)
        where TContext : DbContext
    {
        ((DbContextOptionsBuilder) builder).UseOpenIddict();
        return builder;
    }

    /// <summary>
    /// Registers the OpenIddict entity sets in the Entity Framework Core
    /// context using the default OpenIddict models and the specified key type.
    /// </summary>
    /// <remarks>
    /// Note: when using a custom key type, the new key type MUST be registered by calling
    /// <see cref="OpenIddictEntityFrameworkCoreBuilder.ReplaceDefaultEntities{TKey}"/>.
    /// </remarks>
    /// <param name="builder">The builder used to configure the Entity Framework context.</param>
    /// <returns>The Entity Framework context builder.</returns>
    public static DbContextOptionsBuilder UseOpenIddict<TKey>(this DbContextOptionsBuilder builder)
        where TKey : notnull, IEquatable<TKey>
        => builder.UseOpenIddict<OpenIddictEntityFrameworkCoreApplication<TKey>,
                                 OpenIddictEntityFrameworkCoreAuthorization<TKey>,
                                 OpenIddictEntityFrameworkCoreScope<TKey>,
                                 OpenIddictEntityFrameworkCoreToken<TKey>, TKey>();

    /// <summary>
    /// Registers the OpenIddict entity sets in the Entity Framework Core 
    /// context using the default OpenIddict models and the specified key type.
    /// </summary>
    /// <remarks>
    /// Note: when using a custom key type, the new key type MUST be registered by calling
    /// <see cref="OpenIddictEntityFrameworkCoreBuilder.ReplaceDefaultEntities{TKey}"/>.
    /// </remarks>
    /// <param name="builder">The builder used to configure the Entity Framework context.</param>
    /// <returns>The Entity Framework context builder.</returns>
    public static DbContextOptionsBuilder<TContext> UseOpenIddict<TKey, TContext>(this DbContextOptionsBuilder<TContext> builder)
        where TKey : notnull, IEquatable<TKey>
        where TContext : DbContext
    {
        builder.UseOpenIddict<TKey>();
        return builder;
    }

    /// <summary>
    /// Registers the OpenIddict entity sets in the Entity Framework Core
    /// context using the specified entities and the specified key type.
    /// </summary>
    /// <remarks>
    /// Note: when using custom entities, the new entities MUST be registered by calling
    /// <see cref="OpenIddictEntityFrameworkCoreBuilder.ReplaceDefaultEntities{TApplication, TAuthorization, TScope, TToken, TKey}"/>.
    /// </remarks>
    /// <param name="builder">The builder used to configure the Entity Framework context.</param>
    /// <returns>The Entity Framework context builder.</returns>
    public static DbContextOptionsBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>(
        this DbContextOptionsBuilder builder)
        where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
        where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
        where TScope : OpenIddictEntityFrameworkCoreScope<TKey>
        where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
        where TKey : notnull, IEquatable<TKey>
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        return builder.ReplaceService<IModelCustomizer, OpenIddictEntityFrameworkCoreCustomizer<
            TApplication, TAuthorization, TScope, TToken, TKey>>();
    }

    /// <summary>
    /// Registers the OpenIddict entity sets in the Entity Framework Core
    /// context using the specified entities and the specified key type.
    /// </summary>
    /// <remarks>
    /// Note: when using custom entities, the new entities MUST be registered by calling
    /// <see cref="OpenIddictEntityFrameworkCoreBuilder.ReplaceDefaultEntities{TApplication, TAuthorization, TScope, TToken, TKey}"/>.
    /// </remarks>
    /// <param name="builder">The builder used to configure the Entity Framework context.</param>
    /// <returns>The Entity Framework context builder.</returns>
    public static DbContextOptionsBuilder<TContext> UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey, TContext>(
        this DbContextOptionsBuilder<TContext> builder)
        where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
        where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
        where TScope : OpenIddictEntityFrameworkCoreScope<TKey>
        where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
        where TKey : notnull, IEquatable<TKey>
        where TContext : DbContext
    {
        builder.UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>();
        return builder;
    }

    /// <summary>
    /// Registers the OpenIddict entity sets in the Entity Framework Core context
    /// using the default OpenIddict models and the default key type (string).
    /// </summary>
    /// <param name="builder">The builder used to configure the Entity Framework context.</param>
    /// <returns>The Entity Framework context builder.</returns>
    public static ModelBuilder UseOpenIddict(this ModelBuilder builder)
        => builder.UseOpenIddict<OpenIddictEntityFrameworkCoreApplication,
                                 OpenIddictEntityFrameworkCoreAuthorization,
                                 OpenIddictEntityFrameworkCoreScope,
                                 OpenIddictEntityFrameworkCoreToken, string>();

    /// <summary>
    /// Registers the OpenIddict entity sets in the Entity Framework Core
    /// context using the default OpenIddict models and the specified key type.
    /// </summary>
    /// <remarks>
    /// Note: when using a custom key type, the new key type MUST be registered by calling
    /// <see cref="OpenIddictEntityFrameworkCoreBuilder.ReplaceDefaultEntities{TKey}"/>.
    /// </remarks>
    /// <param name="builder">The builder used to configure the Entity Framework context.</param>
    /// <returns>The Entity Framework context builder.</returns>
    public static ModelBuilder UseOpenIddict<TKey>(this ModelBuilder builder) where TKey : notnull, IEquatable<TKey>
        => builder.UseOpenIddict<OpenIddictEntityFrameworkCoreApplication<TKey>,
                                 OpenIddictEntityFrameworkCoreAuthorization<TKey>,
                                 OpenIddictEntityFrameworkCoreScope<TKey>,
                                 OpenIddictEntityFrameworkCoreToken<TKey>, TKey>();

    /// <summary>
    /// Registers the OpenIddict entity sets in the Entity Framework Core
    /// context using the specified entities and the specified key type.
    /// </summary>
    /// <remarks>
    /// Note: when using custom entities, the new entities MUST be registered by calling
    /// <see cref="OpenIddictEntityFrameworkCoreBuilder.ReplaceDefaultEntities{TApplication, TAuthorization, TScope, TToken, TKey}"/>.
    /// </remarks>
    /// <param name="builder">The builder used to configure the Entity Framework context.</param>
    /// <returns>The Entity Framework context builder.</returns>
    public static ModelBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>(this ModelBuilder builder)
        where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
        where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
        where TScope : OpenIddictEntityFrameworkCoreScope<TKey>
        where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
        where TKey : notnull, IEquatable<TKey>
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        return builder
            .ApplyConfiguration(new OpenIddictEntityFrameworkCoreApplicationConfiguration<TApplication, TAuthorization, TToken, TKey>())
            .ApplyConfiguration(new OpenIddictEntityFrameworkCoreAuthorizationConfiguration<TAuthorization, TApplication, TToken, TKey>())
            .ApplyConfiguration(new OpenIddictEntityFrameworkCoreScopeConfiguration<TScope, TKey>())
            .ApplyConfiguration(new OpenIddictEntityFrameworkCoreTokenConfiguration<TToken, TApplication, TAuthorization, TKey>());
    }

#if SUPPORTS_BCL_ASYNC_ENUMERABLE
    /// <summary>
    /// Executes the query and returns the results as a streamed async enumeration.
    /// </summary>
    /// <typeparam name="T">The type of the returned entities.</typeparam>
    /// <param name="source">The query source.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The non-streamed async enumeration containing the results.</returns>
#else
    /// <summary>
    /// Executes the query and returns the results as a non-streamed async enumeration.
    /// </summary>
    /// <typeparam name="T">The type of the returned entities.</typeparam>
    /// <param name="source">The query source.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The non-streamed async enumeration containing the results.</returns>
#endif
    internal static IAsyncEnumerable<T> AsAsyncEnumerable<T>(this IQueryable<T> source, CancellationToken cancellationToken)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        return ExecuteAsync(source, cancellationToken);

        static async IAsyncEnumerable<T> ExecuteAsync(IQueryable<T> source, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
#if SUPPORTS_BCL_ASYNC_ENUMERABLE
            await foreach (var element in source.AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return element;
            }
#else
            foreach (var element in await source.ToListAsync(cancellationToken))
            {
                yield return element;
            }
#endif
        }
    }

    /// <summary>
    /// Tries to create a new <see cref="IDbContextTransaction"/> with the specified <paramref name="level"/>.
    /// </summary>
    /// <param name="context">The Entity Framework Core context.</param>
    /// <param name="level">The desired level of isolation.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The <see cref="IDbContextTransaction"/> if it could be created, <see langword="null"/> otherwise.</returns>
    internal static async ValueTask<IDbContextTransaction?> CreateTransactionAsync(
        this DbContext context, IsolationLevel level, CancellationToken cancellationToken)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        // Note: transactions that specify an explicit isolation level are only supported by
        // relational providers and trying to use them with a different provider results in
        // an invalid operation exception being thrown at runtime. To prevent that, a manual
        // check is made to ensure the underlying transaction manager is relational.
        var manager = context.Database.GetService<IDbContextTransactionManager>();
        if (manager is IRelationalTransactionManager)
        {
            try
            {
                return await context.Database.BeginTransactionAsync(level, cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                return null;
            }
        }

        return null;
    }
}
