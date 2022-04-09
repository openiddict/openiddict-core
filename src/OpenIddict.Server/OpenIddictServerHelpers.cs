/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server;

/// <summary>
/// Exposes extensions simplifying the integration with the OpenIddict server services.
/// </summary>
public static class OpenIddictServerHelpers
{
    /// <summary>
    /// Retrieves a property value from the server transaction using the specified name.
    /// </summary>
    /// <typeparam name="TProperty">The type of the property.</typeparam>
    /// <param name="transaction">The server transaction.</param>
    /// <param name="name">The property name.</param>
    /// <returns>The property value or <see langword="null"/> if it couldn't be found.</returns>
    public static TProperty? GetProperty<TProperty>(
        this OpenIddictServerTransaction transaction!!, string name) where TProperty : class
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0106), nameof(name));
        }

        if (transaction.Properties.TryGetValue(name, out var property) && property is TProperty result)
        {
            return result;
        }

        return null;
    }

    /// <summary>
    /// Sets a property in the server transaction using the specified name and value.
    /// </summary>
    /// <typeparam name="TProperty">The type of the property.</typeparam>
    /// <param name="transaction">The server transaction.</param>
    /// <param name="name">The property name.</param>
    /// <param name="value">The property value.</param>
    /// <returns>The server transaction, so that calls can be easily chained.</returns>
    public static OpenIddictServerTransaction SetProperty<TProperty>(
        this OpenIddictServerTransaction transaction!!,
        string name, TProperty? value) where TProperty : class
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0106), nameof(name));
        }

        if (value is null)
        {
            transaction.Properties.Remove(name);
        }

        else
        {
            transaction.Properties[name] = value;
        }

        return transaction;
    }
}
