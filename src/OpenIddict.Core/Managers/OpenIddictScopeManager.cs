/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Core;

/// <summary>
/// Provides methods allowing to manage the scopes stored in the store.
/// </summary>
/// <remarks>
/// Applications that do not want to depend on a specific entity type can use the non-generic
/// <see cref="IOpenIddictScopeManager"/> instead, for which the actual entity type
/// is resolved at runtime based on the default entity type registered in the core options.
/// </remarks>
/// <typeparam name="TScope">The type of the Scope entity.</typeparam>
public class OpenIddictScopeManager<TScope> : IOpenIddictScopeManager where TScope : class
{
    public OpenIddictScopeManager(
        IOpenIddictScopeCache<TScope> cache!!,
        ILogger<OpenIddictScopeManager<TScope>> logger!!,
        IOptionsMonitor<OpenIddictCoreOptions> options!!,
        IOpenIddictScopeStoreResolver resolver!!)
    {
        Cache = cache;
        Logger = logger;
        Options = options;
        Store = resolver.Get<TScope>();
    }

    /// <summary>
    /// Gets the cache associated with the current manager.
    /// </summary>
    protected IOpenIddictScopeCache<TScope> Cache { get; }

    /// <summary>
    /// Gets the logger associated with the current manager.
    /// </summary>
    protected ILogger Logger { get; }

    /// <summary>
    /// Gets the options associated with the current manager.
    /// </summary>
    protected IOptionsMonitor<OpenIddictCoreOptions> Options { get; }

    /// <summary>
    /// Gets the store associated with the current manager.
    /// </summary>
    protected IOpenIddictScopeStore<TScope> Store { get; }

    /// <summary>
    /// Determines the number of scopes that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of scopes in the database.
    /// </returns>
    public virtual ValueTask<long> CountAsync(CancellationToken cancellationToken = default)
        => Store.CountAsync(cancellationToken);

    /// <summary>
    /// Determines the number of scopes that match the specified query.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of scopes that match the specified query.
    /// </returns>
    public virtual ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<TScope>, IQueryable<TResult>> query!!, CancellationToken cancellationToken = default)
        => Store.CountAsync(query, cancellationToken);

    /// <summary>
    /// Creates a new scope.
    /// </summary>
    /// <param name="scope">The scope to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask CreateAsync(TScope scope!!, CancellationToken cancellationToken = default)
    {
        var results = await GetValidationResultsAsync(scope, cancellationToken);
        if (results.Any(result => result != ValidationResult.Success))
        {
            var builder = new StringBuilder();
            builder.AppendLine(SR.GetResourceString(SR.ID0222));
            builder.AppendLine();

            foreach (var result in results)
            {
                builder.AppendLine(result.ErrorMessage);
            }

            throw new OpenIddictExceptions.ValidationException(builder.ToString(), results);
        }

        await Store.CreateAsync(scope, cancellationToken);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.AddAsync(scope, cancellationToken);
        }

        async Task<ImmutableArray<ValidationResult>> GetValidationResultsAsync(
            TScope scope, CancellationToken cancellationToken)
        {
            var builder = ImmutableArray.CreateBuilder<ValidationResult>();

            await foreach (var result in ValidateAsync(scope, cancellationToken))
            {
                builder.Add(result);
            }

            return builder.ToImmutable();
        }
    }

    /// <summary>
    /// Creates a new scope based on the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The scope descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation, whose result returns the scope.
    /// </returns>
    public virtual async ValueTask<TScope> CreateAsync(
        OpenIddictScopeDescriptor descriptor!!, CancellationToken cancellationToken = default)
    {
        var scope = await Store.InstantiateAsync(cancellationToken);
        if (scope is null)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0223));
        }

        await PopulateAsync(scope, descriptor, cancellationToken);
        await CreateAsync(scope, cancellationToken);

        return scope;
    }

    /// <summary>
    /// Removes an existing scope.
    /// </summary>
    /// <param name="scope">The scope to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask DeleteAsync(TScope scope!!, CancellationToken cancellationToken = default)
    {
        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.RemoveAsync(scope, cancellationToken);
        }

        await Store.DeleteAsync(scope, cancellationToken);
    }

    /// <summary>
    /// Retrieves a scope using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the scope corresponding to the identifier.
    /// </returns>
    public virtual async ValueTask<TScope?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var scope = Options.CurrentValue.DisableEntityCaching ?
            await Store.FindByIdAsync(identifier, cancellationToken) :
            await Cache.FindByIdAsync(identifier, cancellationToken);

        if (scope is null)
        {
            return null;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.
        if (!Options.CurrentValue.DisableAdditionalFiltering &&
            !string.Equals(await Store.GetIdAsync(scope, cancellationToken), identifier, StringComparison.Ordinal))
        {
            return null;
        }

        return scope;
    }

    /// <summary>
    /// Retrieves a scope using its name.
    /// </summary>
    /// <param name="name">The name associated with the scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the scope corresponding to the specified name.
    /// </returns>
    public virtual async ValueTask<TScope?> FindByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0202), nameof(name));
        }

        var scope = Options.CurrentValue.DisableEntityCaching ?
            await Store.FindByNameAsync(name, cancellationToken) :
            await Cache.FindByNameAsync(name, cancellationToken);

        if (scope is null)
        {
            return null;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        if (!Options.CurrentValue.DisableAdditionalFiltering &&
            !string.Equals(await Store.GetNameAsync(scope, cancellationToken), name, StringComparison.Ordinal))
        {
            return null;
        }

        return scope;
    }

    /// <summary>
    /// Retrieves a list of scopes using their name.
    /// </summary>
    /// <param name="names">The names associated with the scopes.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The scopes corresponding to the specified names.</returns>
    public virtual IAsyncEnumerable<TScope> FindByNamesAsync(
        ImmutableArray<string> names, CancellationToken cancellationToken = default)
    {
        if (names.Any(string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0203), nameof(names));
        }

        var scopes = Options.CurrentValue.DisableEntityCaching ?
            Store.FindByNamesAsync(names, cancellationToken) :
            Cache.FindByNamesAsync(names, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return scopes;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TScope> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var scope in scopes)
            {
                if (names.Contains(await Store.GetNameAsync(scope, cancellationToken), StringComparer.Ordinal))
                {
                    yield return scope;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves all the scopes that contain the specified resource.
    /// </summary>
    /// <param name="resource">The resource associated with the scopes.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The scopes associated with the specified resource.</returns>
    public virtual IAsyncEnumerable<TScope> FindByResourceAsync(
        string resource, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(resource))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0062), nameof(resource));
        }

        var scopes = Options.CurrentValue.DisableEntityCaching ?
            Store.FindByResourceAsync(resource, cancellationToken) :
            Cache.FindByResourceAsync(resource, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return scopes;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TScope> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var scope in scopes)
            {
                var resources = await Store.GetResourcesAsync(scope, cancellationToken);
                if (resources.Contains(resource, StringComparer.Ordinal))
                {
                    yield return scope;
                }
            }
        }
    }

    /// <summary>
    /// Executes the specified query and returns the first element.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the first element returned when executing the query.
    /// </returns>
    public virtual ValueTask<TResult?> GetAsync<TResult>(
        Func<IQueryable<TScope>, IQueryable<TResult>> query!!, CancellationToken cancellationToken = default)
        => GetAsync(static (scopes, query) => query(scopes), query, cancellationToken);

    /// <summary>
    /// Executes the specified query and returns the first element.
    /// </summary>
    /// <typeparam name="TState">The state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="state">The optional state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the first element returned when executing the query.
    /// </returns>
    public virtual ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TScope>, TState, IQueryable<TResult>> query!!,
        TState state, CancellationToken cancellationToken = default)
        => Store.GetAsync(query, state, cancellationToken);

    /// <summary>
    /// Retrieves the description associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the description associated with the specified scope.
    /// </returns>
    public virtual ValueTask<string?> GetDescriptionAsync(TScope scope!!, CancellationToken cancellationToken = default)
        => Store.GetDescriptionAsync(scope, cancellationToken);

    /// <summary>
    /// Retrieves the localized descriptions associated with an scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the localized descriptions associated with the scope.
    /// </returns>
    public virtual async ValueTask<ImmutableDictionary<CultureInfo, string>> GetDescriptionsAsync(
        TScope scope!!, CancellationToken cancellationToken = default)
        => await Store.GetDescriptionsAsync(scope, cancellationToken) is { Count: > 0 } descriptions ?
            descriptions : ImmutableDictionary.Create<CultureInfo, string>();

    /// <summary>
    /// Retrieves the display name associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the display name associated with the scope.
    /// </returns>
    public virtual ValueTask<string?> GetDisplayNameAsync(TScope scope!!, CancellationToken cancellationToken = default)
        => Store.GetDisplayNameAsync(scope, cancellationToken);

    /// <summary>
    /// Retrieves the localized display names associated with an scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the localized display names associated with the scope.
    /// </returns>
    public virtual async ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(
        TScope scope!!, CancellationToken cancellationToken = default)
        => await Store.GetDisplayNamesAsync(scope, cancellationToken) is { Count: > 0 } names ?
            names : ImmutableDictionary.Create<CultureInfo, string>();

    /// <summary>
    /// Retrieves the unique identifier associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the scope.
    /// </returns>
    public virtual ValueTask<string?> GetIdAsync(TScope scope!!, CancellationToken cancellationToken = default)
        => Store.GetIdAsync(scope, cancellationToken);

    /// <summary>
    /// Retrieves the localized display name associated with an scope
    /// and corresponding to the current UI culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the matching display name associated with the scope.
    /// </returns>
    public virtual ValueTask<string?> GetLocalizedDisplayNameAsync(TScope scope, CancellationToken cancellationToken = default)
        => GetLocalizedDisplayNameAsync(scope, CultureInfo.CurrentUICulture, cancellationToken);

    /// <summary>
    /// Retrieves the localized display name associated with an scope
    /// and corresponding to the specified culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="culture">The culture (typically <see cref="CultureInfo.CurrentUICulture"/>).</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the matching display name associated with the scope.
    /// </returns>
    public virtual async ValueTask<string?> GetLocalizedDisplayNameAsync(
        TScope scope!!, CultureInfo culture!!, CancellationToken cancellationToken = default)
    {
        var names = await Store.GetDisplayNamesAsync(scope, cancellationToken);
        if (names is not { IsEmpty: false })
        {
            return await Store.GetDisplayNameAsync(scope, cancellationToken);
        }

        do
        {
            if (names.TryGetValue(culture, out var name))
            {
                return name;
            }

            culture = culture.Parent;
        }

        while (culture != CultureInfo.InvariantCulture);

        return await Store.GetDisplayNameAsync(scope, cancellationToken);
    }

    /// <summary>
    /// Retrieves the localized description associated with an scope
    /// and corresponding to the current UI culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the matching localized description associated with the scope.
    /// </returns>
    public virtual ValueTask<string?> GetLocalizedDescriptionAsync(TScope scope, CancellationToken cancellationToken = default)
        => GetLocalizedDescriptionAsync(scope, CultureInfo.CurrentUICulture, cancellationToken);

    /// <summary>
    /// Retrieves the localized description associated with an scope
    /// and corresponding to the specified culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="culture">The culture (typically <see cref="CultureInfo.CurrentUICulture"/>).</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the matching localized description associated with the scope.
    /// </returns>
    public virtual async ValueTask<string?> GetLocalizedDescriptionAsync(
        TScope scope!!, CultureInfo culture!!, CancellationToken cancellationToken = default)
    {
        var descriptions = await Store.GetDescriptionsAsync(scope, cancellationToken);
        if (descriptions is not { IsEmpty: false })
        {
            return await Store.GetDescriptionAsync(scope, cancellationToken);
        }

        do
        {
            if (descriptions.TryGetValue(culture, out var description))
            {
                return description;
            }

            culture = culture.Parent;
        }

        while (culture != CultureInfo.InvariantCulture);

        return await Store.GetDescriptionAsync(scope, cancellationToken);
    }

    /// <summary>
    /// Retrieves the name associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the name associated with the specified scope.
    /// </returns>
    public virtual ValueTask<string?> GetNameAsync(TScope scope!!, CancellationToken cancellationToken = default)
        => Store.GetNameAsync(scope, cancellationToken);

    /// <summary>
    /// Retrieves the additional properties associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the scope.
    /// </returns>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        TScope scope!!, CancellationToken cancellationToken = default)
        => Store.GetPropertiesAsync(scope, cancellationToken);

    /// <summary>
    /// Retrieves the resources associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the resources associated with the scope.
    /// </returns>
    public virtual ValueTask<ImmutableArray<string>> GetResourcesAsync(
        TScope scope!!, CancellationToken cancellationToken = default)
        => Store.GetResourcesAsync(scope, cancellationToken);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    public virtual IAsyncEnumerable<TScope> ListAsync(
        int? count = null, int? offset = null, CancellationToken cancellationToken = default)
        => Store.ListAsync(count, offset, cancellationToken);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    public virtual IAsyncEnumerable<TResult> ListAsync<TResult>(
        Func<IQueryable<TScope>, IQueryable<TResult>> query!!, CancellationToken cancellationToken = default)
        => ListAsync(static (scopes, query) => query(scopes), query, cancellationToken);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <typeparam name="TState">The state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="state">The optional state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TScope>, TState, IQueryable<TResult>> query!!,
        TState state, CancellationToken cancellationToken = default)
        => Store.ListAsync(query, state, cancellationToken);

    /// <summary>
    /// Lists all the resources associated with the specified scopes.
    /// </summary>
    /// <param name="scopes">The scopes.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the resources associated with the specified scopes.</returns>
    public virtual async IAsyncEnumerable<string> ListResourcesAsync(
        ImmutableArray<string> scopes, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var resources = new HashSet<string>(StringComparer.Ordinal);

        await foreach (var scope in FindByNamesAsync(scopes, cancellationToken))
        {
            resources.UnionWith(await GetResourcesAsync(scope, cancellationToken));
        }

        foreach (var resource in resources)
        {
            yield return resource;
        }
    }

    /// <summary>
    /// Populates the scope using the specified descriptor.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask PopulateAsync(TScope scope!!,
        OpenIddictScopeDescriptor descriptor!!, CancellationToken cancellationToken = default)
    {
        await Store.SetDescriptionAsync(scope, descriptor.Description, cancellationToken);
        await Store.SetDescriptionsAsync(scope, descriptor.Descriptions.ToImmutableDictionary(), cancellationToken);
        await Store.SetDisplayNameAsync(scope, descriptor.DisplayName, cancellationToken);
        await Store.SetDisplayNamesAsync(scope, descriptor.DisplayNames.ToImmutableDictionary(), cancellationToken);
        await Store.SetNameAsync(scope, descriptor.Name, cancellationToken);
        await Store.SetPropertiesAsync(scope, descriptor.Properties.ToImmutableDictionary(), cancellationToken);
        await Store.SetResourcesAsync(scope, descriptor.Resources.ToImmutableArray(), cancellationToken);
    }

    /// <summary>
    /// Populates the specified descriptor using the properties exposed by the scope.
    /// </summary>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask PopulateAsync(
        OpenIddictScopeDescriptor descriptor!!,
        TScope scope!!, CancellationToken cancellationToken = default)
    {
        descriptor.Description = await Store.GetDescriptionAsync(scope, cancellationToken);
        descriptor.DisplayName = await Store.GetDisplayNameAsync(scope, cancellationToken);
        descriptor.Name = await Store.GetNameAsync(scope, cancellationToken);
        descriptor.Resources.Clear();
        descriptor.Resources.UnionWith(await Store.GetResourcesAsync(scope, cancellationToken));

        descriptor.DisplayNames.Clear();
        foreach (var pair in await Store.GetDisplayNamesAsync(scope, cancellationToken))
        {
            descriptor.DisplayNames.Add(pair.Key, pair.Value);
        }

        descriptor.Descriptions.Clear();
        foreach (var pair in await Store.GetDescriptionsAsync(scope, cancellationToken))
        {
            descriptor.Descriptions.Add(pair.Key, pair.Value);
        }

        descriptor.Properties.Clear();
        foreach (var pair in await Store.GetPropertiesAsync(scope, cancellationToken))
        {
            descriptor.Properties.Add(pair.Key, pair.Value);
        }
    }

    /// <summary>
    /// Updates an existing scope.
    /// </summary>
    /// <param name="scope">The scope to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask UpdateAsync(TScope scope!!, CancellationToken cancellationToken = default)
    {
        var results = await GetValidationResultsAsync(scope, cancellationToken);
        if (results.Any(result => result != ValidationResult.Success))
        {
            var builder = new StringBuilder();
            builder.AppendLine(SR.GetResourceString(SR.ID0224));
            builder.AppendLine();

            foreach (var result in results)
            {
                builder.AppendLine(result.ErrorMessage);
            }

            throw new OpenIddictExceptions.ValidationException(builder.ToString(), results);
        }

        await Store.UpdateAsync(scope, cancellationToken);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.RemoveAsync(scope, cancellationToken);
            await Cache.AddAsync(scope, cancellationToken);
        }

        async Task<ImmutableArray<ValidationResult>> GetValidationResultsAsync(
            TScope scope, CancellationToken cancellationToken)
        {
            var builder = ImmutableArray.CreateBuilder<ValidationResult>();

            await foreach (var result in ValidateAsync(scope, cancellationToken))
            {
                builder.Add(result);
            }

            return builder.ToImmutable();
        }
    }

    /// <summary>
    /// Updates an existing scope.
    /// </summary>
    /// <param name="scope">The scope to update.</param>
    /// <param name="descriptor">The descriptor used to update the scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask UpdateAsync(TScope scope!!,
        OpenIddictScopeDescriptor descriptor!!, CancellationToken cancellationToken = default)
    {
        await PopulateAsync(scope, descriptor, cancellationToken);
        await UpdateAsync(scope, cancellationToken);
    }

    /// <summary>
    /// Validates the scope to ensure it's in a consistent state.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation error encountered when validating the scope.</returns>
    public virtual async IAsyncEnumerable<ValidationResult> ValidateAsync(
        TScope scope!!, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        // Ensure the name is not null or empty, does not contain a
        // space and is not already used for a different scope entity.
        var name = await Store.GetNameAsync(scope, cancellationToken);
        if (string.IsNullOrEmpty(name))
        {
            yield return new ValidationResult(SR.GetResourceString(SR.ID2044));
        }

        else if (name!.Contains(Separators.Space[0]))
        {
            yield return new ValidationResult(SR.GetResourceString(SR.ID2045));
        }

        else
        {
            // Note: depending on the database/table/query collation used by the store, a scope
            // whose name doesn't exactly match the specified value may be returned (e.g because
            // the casing is different). To avoid issues when the scope name is part of an index
            // using the same collation, an error is added even if the two names don't exactly match.
            var other = await Store.FindByNameAsync(name, cancellationToken);
            if (other is not null && !string.Equals(
                await Store.GetIdAsync(other, cancellationToken),
                await Store.GetIdAsync(scope, cancellationToken), StringComparison.Ordinal))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2060));
            }
        }
    }

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictScopeManager.CountAsync(CancellationToken cancellationToken)
        => CountAsync(cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictScopeManager.CountAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => CountAsync(query, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object> IOpenIddictScopeManager.CreateAsync(OpenIddictScopeDescriptor descriptor, CancellationToken cancellationToken)
        => await CreateAsync(descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictScopeManager.CreateAsync(object scope, CancellationToken cancellationToken)
        => CreateAsync((TScope) scope, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictScopeManager.DeleteAsync(object scope, CancellationToken cancellationToken)
        => DeleteAsync((TScope) scope, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object?> IOpenIddictScopeManager.FindByIdAsync(string identifier, CancellationToken cancellationToken)
        => await FindByIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object?> IOpenIddictScopeManager.FindByNameAsync(string name, CancellationToken cancellationToken)
        => await FindByNameAsync(name, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictScopeManager.FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken)
        => FindByNamesAsync(names, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictScopeManager.FindByResourceAsync(string resource, CancellationToken cancellationToken)
        => FindByResourceAsync(resource, cancellationToken);

    /// <inheritdoc/>
    ValueTask<TResult?> IOpenIddictScopeManager.GetAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken) where TResult : default
        => GetAsync(query, cancellationToken);

    /// <inheritdoc/>
    ValueTask<TResult?> IOpenIddictScopeManager.GetAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) where TResult : default
        => GetAsync(query, state, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictScopeManager.GetDescriptionAsync(object scope, CancellationToken cancellationToken)
        => GetDescriptionAsync((TScope) scope, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableDictionary<CultureInfo, string>> IOpenIddictScopeManager.GetDescriptionsAsync(object scope, CancellationToken cancellationToken)
        => GetDescriptionsAsync((TScope) scope, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictScopeManager.GetDisplayNameAsync(object scope, CancellationToken cancellationToken)
        => GetDisplayNameAsync((TScope) scope, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableDictionary<CultureInfo, string>> IOpenIddictScopeManager.GetDisplayNamesAsync(object scope, CancellationToken cancellationToken)
        => GetDisplayNamesAsync((TScope) scope, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictScopeManager.GetIdAsync(object scope, CancellationToken cancellationToken)
        => GetIdAsync((TScope) scope, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictScopeManager.GetLocalizedDescriptionAsync(object scope, CancellationToken cancellationToken)
        => GetLocalizedDescriptionAsync((TScope) scope, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictScopeManager.GetLocalizedDescriptionAsync(object scope, CultureInfo culture, CancellationToken cancellationToken)
        => GetLocalizedDescriptionAsync((TScope) scope, culture, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictScopeManager.GetLocalizedDisplayNameAsync(object scope, CancellationToken cancellationToken)
        => GetLocalizedDisplayNameAsync((TScope) scope, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictScopeManager.GetLocalizedDisplayNameAsync(object scope, CultureInfo culture, CancellationToken cancellationToken)
        => GetLocalizedDisplayNameAsync((TScope) scope, culture, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictScopeManager.GetNameAsync(object scope, CancellationToken cancellationToken)
        => GetNameAsync((TScope) scope, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableDictionary<string, JsonElement>> IOpenIddictScopeManager.GetPropertiesAsync(object scope, CancellationToken cancellationToken)
        => GetPropertiesAsync((TScope) scope, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableArray<string>> IOpenIddictScopeManager.GetResourcesAsync(object scope, CancellationToken cancellationToken)
        => GetResourcesAsync((TScope) scope, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictScopeManager.ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        => ListAsync(count, offset, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<TResult> IOpenIddictScopeManager.ListAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => ListAsync(query, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<TResult> IOpenIddictScopeManager.ListAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken)
        => ListAsync(query, state, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<string> IOpenIddictScopeManager.ListResourcesAsync(ImmutableArray<string> scopes, CancellationToken cancellationToken)
        => ListResourcesAsync(scopes, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictScopeManager.PopulateAsync(OpenIddictScopeDescriptor descriptor, object scope, CancellationToken cancellationToken)
        => PopulateAsync(descriptor, (TScope) scope, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictScopeManager.PopulateAsync(object scope, OpenIddictScopeDescriptor descriptor, CancellationToken cancellationToken)
        => PopulateAsync((TScope) scope, descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictScopeManager.UpdateAsync(object scope, CancellationToken cancellationToken)
        => UpdateAsync((TScope) scope, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictScopeManager.UpdateAsync(object scope, OpenIddictScopeDescriptor descriptor, CancellationToken cancellationToken)
        => UpdateAsync((TScope) scope, descriptor, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<ValidationResult> IOpenIddictScopeManager.ValidateAsync(object scope, CancellationToken cancellationToken)
        => ValidateAsync((TScope) scope, cancellationToken);
}
