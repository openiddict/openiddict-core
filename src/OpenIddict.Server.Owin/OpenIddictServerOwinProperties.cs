/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using Microsoft.Owin.Security;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.Owin
{
    /// <inheritdoc/>
    public class OpenIddictServerOwinProperties : AuthenticationProperties
    {
        /// <inheritdoc/>
        public OpenIddictServerOwinProperties()
            : this(items: null)
        {
        }

        /// <inheritdoc/>
        public OpenIddictServerOwinProperties(IDictionary<string, string?>? items)
            : this(items, parameters: null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIddictServerOwinProperties"/> class.
        /// </summary>
        /// <param name="items">State values dictionary to use.</param>
        /// <param name="parameters">Parameters dictionary to use.</param>
        public OpenIddictServerOwinProperties(
            IDictionary<string, string?>? items,
            IDictionary<string, object?>? parameters)
            : base(items)
            => Parameters = parameters is not null ?
                new(parameters, StringComparer.Ordinal) :
                new(StringComparer.Ordinal);

        /// <summary>
        /// Gets the collection of parameters passed to the authentication handler.
        /// </summary>
        /// <remarks>
        /// Note: these properties are not intended for serialization or persistence,
        /// only for flowing data between call sites.
        /// </remarks>
        public Dictionary<string, object?> Parameters { get; }

        /// <summary>
        /// Gets a parameter from the <see cref="Parameters"/> collection.
        /// </summary>
        /// <typeparam name="T">The parameter type.</typeparam>
        /// <param name="name">The parameter name.</param>
        /// <returns>The parameter value or a default value if the property is not set.</returns>
        public T? GetParameter<T>(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException(SR.ID0190, nameof(name));
            }

            return Parameters.TryGetValue(name, out var parameter) && parameter is T value ? value : default;
        }

        /// <summary>
        /// Sets a parameter value in the <see cref="Parameters"/> collection.
        /// </summary>
        /// <typeparam name="T">The parameter type.</typeparam>
        /// <param name="name">The parameter key.</param>
        /// <param name="value">The value to set.</param>
        public void SetParameter<T>(string name, T? value)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException(SR.ID0190, nameof(name));
            }

            if (value is null)
            {
                Parameters.Remove(name);
            }

            else
            {
                Parameters[name] = value;
            }
        }
    }
}
