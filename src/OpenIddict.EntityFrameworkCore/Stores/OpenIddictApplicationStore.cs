/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Core;
using OpenIddict.Models;

namespace OpenIddict.EntityFrameworkCore
{
    /// <summary>
    /// Provides methods allowing to manage the applications stored in a database.
    /// Note: this class can only be used with the default OpenIddict entities.
    /// </summary>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    public class OpenIddictApplicationStore<TContext> : OpenIddictApplicationStore<OpenIddictApplication,
                                                                                   OpenIddictAuthorization,
                                                                                   OpenIddictToken, TContext, string>
        where TContext : DbContext
    {
        public OpenIddictApplicationStore([NotNull] TContext context) : base(context) { }
    }

    /// <summary>
    /// Provides methods allowing to manage the applications stored in a database.
    /// Note: this class can only be used with the default OpenIddict entities.
    /// </summary>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictApplicationStore<TContext, TKey> : OpenIddictApplicationStore<OpenIddictApplication<TKey>,
                                                                                         OpenIddictAuthorization<TKey>,
                                                                                         OpenIddictToken<TKey>, TContext, TKey>
        where TContext : DbContext
        where TKey : IEquatable<TKey>
    {
        public OpenIddictApplicationStore([NotNull] TContext context) : base(context) { }
    }

    /// <summary>
    /// Provides methods allowing to manage the applications stored in a database.
    /// Note: this class can only be used with the default OpenIddict entities.
    /// </summary>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictApplicationStore<TApplication, TAuthorization, TToken, TContext, TKey> :
        OpenIddictApplicationStore<TApplication, TAuthorization, TToken, TKey>
        where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>, new()
        where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>, new()
        where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>, new()
        where TContext : DbContext
        where TKey : IEquatable<TKey>
    {
        public OpenIddictApplicationStore([NotNull] TContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Context = context;
        }

        /// <summary>
        /// Gets the database context associated with the current store.
        /// </summary>
        protected virtual TContext Context { get; }

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TApplication"/> entity.
        /// </summary>
        protected DbSet<TApplication> Applications => Context.Set<TApplication>();

        /// <summary>
        /// Creates a new application.
        /// </summary>
        /// <param name="application">The application to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result returns the application.
        /// </returns>
        public override async Task<TApplication> CreateAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            Context.Add(application);

            await Context.SaveChangesAsync(cancellationToken);

            return application;
        }

        /// <summary>
        /// Creates a new application.
        /// </summary>
        /// <param name="descriptor">The application descriptor.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result returns the application.
        /// </returns>
        public override Task<TApplication> CreateAsync([NotNull] OpenIddictApplicationDescriptor descriptor, CancellationToken cancellationToken)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            var application = new TApplication
            {
                ClientId = descriptor.ClientId,
                ClientSecret = descriptor.ClientSecret,
                DisplayName = descriptor.DisplayName,
                Type = descriptor.Type
            };

            if (descriptor.PostLogoutRedirectUris.Count != 0)
            {
                application.PostLogoutRedirectUris = string.Join(
                    OpenIddictConstants.Separators.Space,
                    descriptor.PostLogoutRedirectUris.Select(uri => uri.OriginalString));
            }

            if (descriptor.RedirectUris.Count != 0)
            {
                application.RedirectUris = string.Join(
                    OpenIddictConstants.Separators.Space,
                    descriptor.RedirectUris.Select(uri => uri.OriginalString));
            }

            return CreateAsync(application, cancellationToken);
        }

        /// <summary>
        /// Removes an existing application.
        /// </summary>
        /// <param name="application">The application to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public override async Task DeleteAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            Context.Remove(application);

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
            }

            catch (DbUpdateConcurrencyException) { }
        }

        /// <summary>
        /// Retrieves an application using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        public override Task<TApplication> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            return Applications.FindAsync(new object[] { ConvertIdentifierFromString(identifier) }, cancellationToken);
        }

        /// <summary>
        /// Executes the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the single element returned when executing the specified query.
        /// </returns>
        public override Task<TResult> GetAsync<TResult>([NotNull] Func<IQueryable<TApplication>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return query.Invoke(Applications).SingleOrDefaultAsync(cancellationToken);
        }

        /// <summary>
        /// Executes the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public override Task<TResult[]> ListAsync<TResult>([NotNull] Func<IQueryable<TApplication>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return query.Invoke(Applications).ToArrayAsync(cancellationToken);
        }

        /// <summary>
        /// Updates an existing application.
        /// </summary>
        /// <param name="application">The application to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public override async Task UpdateAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            Context.Attach(application);
            Context.Update(application);

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
            }

            catch (DbUpdateConcurrencyException) { }
        }
    }
}