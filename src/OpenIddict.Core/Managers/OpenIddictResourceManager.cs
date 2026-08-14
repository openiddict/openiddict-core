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
using ValidationException = OpenIddict.Abstractions.OpenIddictExceptions.ValidationException;

namespace OpenIddict.Core;

/// <summary>
/// Provides methods allowing to manage the resources stored in the store.
/// </summary>
/// <remarks>
/// Applications that do not want to depend on a specific entity type can use the non-generic
/// <see cref="IOpenIddictResourceManager"/> instead, for which the actual entity type is resolved at runtime.
/// </remarks>
/// <typeparam name="TResource">The type of the resource entity.</typeparam>
public class OpenIddictResourceManager<TResource> : IOpenIddictResourceManager where TResource : class
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictResourceManager{TResource}"/> class.
    /// </summary>
    /// <param name="cache">The cache.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The options.</param>
    /// <param name="store">The store.</param>
    public OpenIddictResourceManager(
        IOpenIddictResourceCache<TResource> cache,
        ILogger<OpenIddictResourceManager<TResource>> logger,
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IOpenIddictResourceStore<TResource> store)
    {
        Cache = cache ?? throw new ArgumentNullException(nameof(cache));
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Options = options ?? throw new ArgumentNullException(nameof(options));
        Store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <summary>
    /// Gets the cache associated with the current manager.
    /// </summary>
    protected IOpenIddictResourceCache<TResource> Cache { get; }

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
    protected IOpenIddictResourceStore<TResource> Store { get; }

    /// <summary>
    /// Determines the number of resources that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of resources in the database.
    /// </returns>
    public virtual ValueTask<long> CountAsync(CancellationToken cancellationToken = default)
        => Store.CountAsync(cancellationToken);

    /// <summary>
    /// Determines the number of resources that match the specified query.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of resources that match the specified query.
    /// </returns>
    public virtual ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<TResource>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return CountAsync(static (resources, query) => query(resources), query, cancellationToken);
    }

    /// <summary>
    /// Determines the number of resources that match the specified query.
    /// </summary>
    /// <typeparam name="TState">The state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="state">The optional state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of resources that match the specified query.
    /// </returns>
    public virtual ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TResource>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return Store.CountAsync(query, state, cancellationToken);
    }

    /// <summary>
    /// Creates a new resource.
    /// </summary>
    /// <param name="resource">The resource to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask CreateAsync(TResource resource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);

        var results = await GetValidationResultsAsync(resource, cancellationToken);
        if (results.Any(static result => result != ValidationResult.Success))
        {
            var builder = new StringBuilder();
            builder.AppendLine(SR.GetResourceString(SR.ID0207));
            builder.AppendLine();

            foreach (var result in results)
            {
                builder.AppendLine(result.ErrorMessage);
            }

            throw new ValidationException(builder.ToString(), results);
        }

        await Store.CreateAsync(resource, cancellationToken);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.AddAsync(resource, cancellationToken);
        }

        async Task<ImmutableArray<ValidationResult>> GetValidationResultsAsync(
            TResource resource, CancellationToken cancellationToken)
        {
            var builder = ImmutableArray.CreateBuilder<ValidationResult>();

            await foreach (var result in ValidateAsync(resource, cancellationToken))
            {
                builder.Add(result);
            }

            return builder.ToImmutable();
        }
    }

    /// <summary>
    /// Creates a new resource based on the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The resource descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation, whose result returns the resource.
    /// </returns>
    public virtual async ValueTask<TResource> CreateAsync(
        OpenIddictResourceDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        var resource = await Store.InstantiateAsync(cancellationToken)
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0208));

        await PopulateAsync(resource, descriptor, cancellationToken);
        await CreateAsync(resource, cancellationToken);

        return resource;
    }

    /// <summary>
    /// Removes an existing resource.
    /// </summary>
    /// <param name="resource">The resource to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask DeleteAsync(TResource resource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.RemoveAsync(resource, cancellationToken);
        }

        await Store.DeleteAsync(resource, cancellationToken);
    }

    /// <summary>
    /// Retrieves a resource using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the resource corresponding to the identifier.
    /// </returns>
    public virtual async ValueTask<TResource?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var resource = Options.CurrentValue.DisableEntityCaching
            ? await Store.FindByIdAsync(identifier, cancellationToken)
            : await Cache.FindByIdAsync(identifier, cancellationToken);

        if (resource is null)
        {
            return null;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.
        if (!Options.CurrentValue.DisableAdditionalFiltering &&
            !string.Equals(await Store.GetIdAsync(resource, cancellationToken), identifier, StringComparison.Ordinal))
        {
            return null;
        }

        return resource;
    }

    /// <summary>
    /// Retrieves a resource using its name.
    /// </summary>
    /// <param name="name">The name associated with the resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the resource corresponding to the specified name.
    /// </returns>
    public virtual async ValueTask<TResource?> FindByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        var resource = Options.CurrentValue.DisableEntityCaching
            ? await Store.FindByNameAsync(name, cancellationToken)
            : await Cache.FindByNameAsync(name, cancellationToken);

        if (resource is null)
        {
            return null;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        if (!Options.CurrentValue.DisableAdditionalFiltering &&
            !string.Equals(await Store.GetNameAsync(resource, cancellationToken), name, StringComparison.Ordinal))
        {
            return null;
        }

        return resource;
    }

    /// <summary>
    /// Retrieves a list of resources using their name.
    /// </summary>
    /// <param name="names">The names associated with the resources.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The resources corresponding to the specified names.</returns>
    public virtual IAsyncEnumerable<TResource> FindByNamesAsync(
        ImmutableArray<string> names, CancellationToken cancellationToken = default)
    {
        if (names.Any(string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0203), nameof(names));
        }

        var resources = Options.CurrentValue.DisableEntityCaching
            ? Store.FindByNamesAsync(names, cancellationToken)
            : Cache.FindByNamesAsync(names, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return resources;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TResource> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var resource in resources.WithCancellation(cancellationToken))
            {
                var name = await Store.GetNameAsync(resource, cancellationToken);
                if (!string.IsNullOrEmpty(name) && names.Contains(name, StringComparer.Ordinal))
                {
                    yield return resource;
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
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the first element returned when executing the query.
    /// </returns>
    public virtual ValueTask<TResult?> GetAsync<TResult>(
        Func<IQueryable<TResource>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return GetAsync(static (resources, query) => query(resources), query, cancellationToken);
    }

    /// <summary>
    /// Executes the specified query and returns the first element.
    /// </summary>
    /// <typeparam name="TState">The state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="state">The optional state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the first element returned when executing the query.
    /// </returns>
    public virtual ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TResource>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return Store.GetAsync(query, state, cancellationToken);
    }

    /// <summary>
    /// Retrieves the description associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the description associated with the specified resource.
    /// </returns>
    public virtual ValueTask<string?> GetDescriptionAsync(TResource resource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return Store.GetDescriptionAsync(resource, cancellationToken);
    }

    /// <summary>
    /// Retrieves the localized descriptions associated with an resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the localized descriptions associated with the resource.
    /// </returns>
    public virtual async ValueTask<ImmutableDictionary<CultureInfo, string>> GetDescriptionsAsync(
        TResource resource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return await Store.GetDescriptionsAsync(resource, cancellationToken) is { IsEmpty: false } descriptions ? descriptions : [];
    }

    /// <summary>
    /// Retrieves the display name associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the display name associated with the resource.
    /// </returns>
    public virtual ValueTask<string?> GetDisplayNameAsync(TResource resource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return Store.GetDisplayNameAsync(resource, cancellationToken);
    }

    /// <summary>
    /// Retrieves the localized display names associated with an resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the localized display names associated with the resource.
    /// </returns>
    public virtual async ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(
        TResource resource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return await Store.GetDisplayNamesAsync(resource, cancellationToken) is { IsEmpty: false } names ? names : [];
    }

    /// <summary>
    /// Retrieves the unique identifier associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the resource.
    /// </returns>
    public virtual ValueTask<string?> GetIdAsync(TResource resource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return Store.GetIdAsync(resource, cancellationToken);
    }

    /// <summary>
    /// Retrieves the localized display name associated with an resource
    /// and corresponding to the current UI culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the matching display name associated with the resource.
    /// </returns>
    public virtual ValueTask<string?> GetLocalizedDisplayNameAsync(TResource resource, CancellationToken cancellationToken = default)
        => GetLocalizedDisplayNameAsync(resource, CultureInfo.CurrentUICulture, cancellationToken);

    /// <summary>
    /// Retrieves the localized display name associated with an resource
    /// and corresponding to the specified culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="culture">The culture (typically <see cref="CultureInfo.CurrentUICulture"/>).</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the matching display name associated with the resource.
    /// </returns>
    public virtual async ValueTask<string?> GetLocalizedDisplayNameAsync(
        TResource resource, CultureInfo culture, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);
        ArgumentNullException.ThrowIfNull(culture);

        var names = await Store.GetDisplayNamesAsync(resource, cancellationToken);
        if (names is not { Count: > 0 })
        {
            return await Store.GetDisplayNameAsync(resource, cancellationToken);
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

        return await Store.GetDisplayNameAsync(resource, cancellationToken);
    }

    /// <summary>
    /// Retrieves the localized description associated with an resource
    /// and corresponding to the current UI culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the matching localized description associated with the resource.
    /// </returns>
    public virtual ValueTask<string?> GetLocalizedDescriptionAsync(TResource resource, CancellationToken cancellationToken = default)
        => GetLocalizedDescriptionAsync(resource, CultureInfo.CurrentUICulture, cancellationToken);

    /// <summary>
    /// Retrieves the localized description associated with an resource
    /// and corresponding to the specified culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="culture">The culture (typically <see cref="CultureInfo.CurrentUICulture"/>).</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the matching localized description associated with the resource.
    /// </returns>
    public virtual async ValueTask<string?> GetLocalizedDescriptionAsync(
        TResource resource, CultureInfo culture, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);
        ArgumentNullException.ThrowIfNull(culture);

        var descriptions = await Store.GetDescriptionsAsync(resource, cancellationToken);
        if (descriptions is not { Count: > 0 })
        {
            return await Store.GetDescriptionAsync(resource, cancellationToken);
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

        return await Store.GetDescriptionAsync(resource, cancellationToken);
    }

    /// <summary>
    /// Retrieves the name associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the name associated with the specified resource.
    /// </returns>
    public virtual ValueTask<string?> GetNameAsync(TResource resource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return Store.GetNameAsync(resource, cancellationToken);
    }

    /// <summary>
    /// Retrieves the additional properties associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the resource.
    /// </returns>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        TResource resource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return Store.GetPropertiesAsync(resource, cancellationToken);
    }

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    public virtual IAsyncEnumerable<TResource> ListAsync(
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
        Func<IQueryable<TResource>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return ListAsync(static (resources, query) => query(resources), query, cancellationToken);
    }

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
        Func<IQueryable<TResource>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return Store.ListAsync(query, state, cancellationToken);
    }

    /// <summary>
    /// Populates the resource using the specified descriptor.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask PopulateAsync(TResource resource,
        OpenIddictResourceDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);
        ArgumentNullException.ThrowIfNull(descriptor);

        await Store.SetDescriptionAsync(resource, descriptor.Description, cancellationToken);
        await Store.SetDescriptionsAsync(resource, descriptor.Descriptions.ToImmutableDictionary(), cancellationToken);
        await Store.SetDisplayNameAsync(resource, descriptor.DisplayName, cancellationToken);
        await Store.SetDisplayNamesAsync(resource, descriptor.DisplayNames.ToImmutableDictionary(), cancellationToken);
        await Store.SetNameAsync(resource, descriptor.Name, cancellationToken);
        await Store.SetPropertiesAsync(resource, descriptor.Properties.ToImmutableDictionary(), cancellationToken);
    }

    /// <summary>
    /// Populates the specified descriptor using the properties exposed by the resource.
    /// </summary>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask PopulateAsync(
        OpenIddictResourceDescriptor descriptor,
        TResource resource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(resource);

        descriptor.Description = await Store.GetDescriptionAsync(resource, cancellationToken);
        descriptor.DisplayName = await Store.GetDisplayNameAsync(resource, cancellationToken);
        descriptor.Name = await Store.GetNameAsync(resource, cancellationToken);

        descriptor.DisplayNames.Clear();
        foreach (var pair in await Store.GetDisplayNamesAsync(resource, cancellationToken))
        {
            descriptor.DisplayNames.Add(pair.Key, pair.Value);
        }

        descriptor.Descriptions.Clear();
        foreach (var pair in await Store.GetDescriptionsAsync(resource, cancellationToken))
        {
            descriptor.Descriptions.Add(pair.Key, pair.Value);
        }

        descriptor.Properties.Clear();
        foreach (var pair in await Store.GetPropertiesAsync(resource, cancellationToken))
        {
            descriptor.Properties.Add(pair.Key, pair.Value);
        }
    }

    /// <summary>
    /// Updates an existing resource.
    /// </summary>
    /// <param name="resource">The resource to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask UpdateAsync(TResource resource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);

        var results = await GetValidationResultsAsync(resource, cancellationToken);
        if (results.Any(static result => result != ValidationResult.Success))
        {
            var builder = new StringBuilder();
            builder.AppendLine(SR.GetResourceString(SR.ID0215));
            builder.AppendLine();

            foreach (var result in results)
            {
                builder.AppendLine(result.ErrorMessage);
            }

            throw new ValidationException(builder.ToString(), results);
        }

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.RemoveAsync(resource, cancellationToken);
        }

        await Store.UpdateAsync(resource, cancellationToken);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.AddAsync(resource, cancellationToken);
        }

        async Task<ImmutableArray<ValidationResult>> GetValidationResultsAsync(
            TResource resource, CancellationToken cancellationToken)
        {
            var builder = ImmutableArray.CreateBuilder<ValidationResult>();

            await foreach (var result in ValidateAsync(resource, cancellationToken))
            {
                builder.Add(result);
            }

            return builder.ToImmutable();
        }
    }

    /// <summary>
    /// Updates an existing resource.
    /// </summary>
    /// <param name="resource">The resource to update.</param>
    /// <param name="descriptor">The descriptor used to update the resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask UpdateAsync(TResource resource,
        OpenIddictResourceDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);
        ArgumentNullException.ThrowIfNull(descriptor);

        await PopulateAsync(resource, descriptor, cancellationToken);
        await UpdateAsync(resource, cancellationToken);
    }

    /// <summary>
    /// Validates the resource to ensure it's in a consistent state.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation error encountered when validating the resource.</returns>
    public virtual IAsyncEnumerable<ValidationResult> ValidateAsync(TResource resource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<ValidationResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            // Ensure the name is not null or empty, does not contain a
            // space and is not already used for a different resource entity.
            var name = await Store.GetNameAsync(resource, cancellationToken);
            if (string.IsNullOrEmpty(name))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2206));
            }

            // Note: resources MUST be absolute URIs and cannot contain a fragment.
            //
            // See https://datatracker.ietf.org/doc/html/rfc8693#section-2.1 for more information.
            else if (!Uri.TryCreate(name, UriKind.Absolute, out Uri? uri) ||
                OpenIddictHelpers.IsImplicitFileUri(uri) || !string.IsNullOrEmpty(uri.Fragment))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2207));
            }

            else
            {
                // Note: depending on the database/table/query collation used by the store, a resource
                // whose name doesn't exactly match the specified value may be returned (e.g because
                // the casing is different). To avoid issues when the resource name is part of an index
                // using the same collation, an error is added even if the two names don't exactly match.
                var other = await Store.FindByNameAsync(name, cancellationToken);
                if (other is not null && !string.Equals(
                    await Store.GetIdAsync(other, cancellationToken),
                    await Store.GetIdAsync(resource, cancellationToken), StringComparison.Ordinal))
                {
                    yield return new ValidationResult(SR.GetResourceString(SR.ID2208));
                }
            }
        }
    }

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictResourceManager.CountAsync(CancellationToken cancellationToken)
        => CountAsync(cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictResourceManager.CountAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => CountAsync(query, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictResourceManager.CountAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken)
        => CountAsync(query, state, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object> IOpenIddictResourceManager.CreateAsync(OpenIddictResourceDescriptor descriptor, CancellationToken cancellationToken)
        => await CreateAsync(descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictResourceManager.CreateAsync(object resource, CancellationToken cancellationToken)
        => CreateAsync((TResource) resource, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictResourceManager.DeleteAsync(object resource, CancellationToken cancellationToken)
        => DeleteAsync((TResource) resource, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object?> IOpenIddictResourceManager.FindByIdAsync(string identifier, CancellationToken cancellationToken)
        => await FindByIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object?> IOpenIddictResourceManager.FindByNameAsync(string name, CancellationToken cancellationToken)
        => await FindByNameAsync(name, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictResourceManager.FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken)
        => FindByNamesAsync(names, cancellationToken);

    /// <inheritdoc/>
    ValueTask<TResult?> IOpenIddictResourceManager.GetAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken) where TResult : default
        => GetAsync(query, cancellationToken);

    /// <inheritdoc/>
    ValueTask<TResult?> IOpenIddictResourceManager.GetAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) where TResult : default
        => GetAsync(query, state, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictResourceManager.GetDescriptionAsync(object resource, CancellationToken cancellationToken)
        => GetDescriptionAsync((TResource) resource, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableDictionary<CultureInfo, string>> IOpenIddictResourceManager.GetDescriptionsAsync(object resource, CancellationToken cancellationToken)
        => GetDescriptionsAsync((TResource) resource, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictResourceManager.GetDisplayNameAsync(object resource, CancellationToken cancellationToken)
        => GetDisplayNameAsync((TResource) resource, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableDictionary<CultureInfo, string>> IOpenIddictResourceManager.GetDisplayNamesAsync(object resource, CancellationToken cancellationToken)
        => GetDisplayNamesAsync((TResource) resource, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictResourceManager.GetIdAsync(object resource, CancellationToken cancellationToken)
        => GetIdAsync((TResource) resource, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictResourceManager.GetLocalizedDescriptionAsync(object resource, CancellationToken cancellationToken)
#pragma warning disable MA0011
        => GetLocalizedDescriptionAsync((TResource) resource, cancellationToken);
#pragma warning restore MA0011

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictResourceManager.GetLocalizedDescriptionAsync(object resource, CultureInfo culture, CancellationToken cancellationToken)
        => GetLocalizedDescriptionAsync((TResource) resource, culture, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictResourceManager.GetLocalizedDisplayNameAsync(object resource, CancellationToken cancellationToken)
#pragma warning disable MA0011
        => GetLocalizedDisplayNameAsync((TResource) resource, cancellationToken);
#pragma warning restore MA0011

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictResourceManager.GetLocalizedDisplayNameAsync(object resource, CultureInfo culture, CancellationToken cancellationToken)
        => GetLocalizedDisplayNameAsync((TResource) resource, culture, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictResourceManager.GetNameAsync(object resource, CancellationToken cancellationToken)
        => GetNameAsync((TResource) resource, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableDictionary<string, JsonElement>> IOpenIddictResourceManager.GetPropertiesAsync(object resource, CancellationToken cancellationToken)
        => GetPropertiesAsync((TResource) resource, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictResourceManager.ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        => ListAsync(count, offset, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<TResult> IOpenIddictResourceManager.ListAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => ListAsync(query, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<TResult> IOpenIddictResourceManager.ListAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken)
        => ListAsync(query, state, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictResourceManager.PopulateAsync(OpenIddictResourceDescriptor descriptor, object resource, CancellationToken cancellationToken)
        => PopulateAsync(descriptor, (TResource) resource, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictResourceManager.PopulateAsync(object resource, OpenIddictResourceDescriptor descriptor, CancellationToken cancellationToken)
        => PopulateAsync((TResource) resource, descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictResourceManager.UpdateAsync(object resource, CancellationToken cancellationToken)
        => UpdateAsync((TResource) resource, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictResourceManager.UpdateAsync(object resource, OpenIddictResourceDescriptor descriptor, CancellationToken cancellationToken)
        => UpdateAsync((TResource) resource, descriptor, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<ValidationResult> IOpenIddictResourceManager.ValidateAsync(object resource, CancellationToken cancellationToken)
        => ValidateAsync((TResource) resource, cancellationToken);
}
