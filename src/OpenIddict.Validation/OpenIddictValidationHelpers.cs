/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Defines a set of commonly used helpers.
    /// Note: this API supports the OpenIddict infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future minor releases.
    /// </summary>
    internal static class OpenIddictValidationHelpers
    {
        /// <summary>
        /// Gets a given property from the authentication properties.
        /// </summary>
        /// <param name="properties">The authentication properties.</param>
        /// <param name="property">The specific property to look for.</param>
        /// <returns>The value corresponding to the property, or <c>null</c> if the property cannot be found.</returns>
        public static string GetProperty([NotNull] this AuthenticationProperties properties, [NotNull] string property)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            if (string.IsNullOrEmpty(property))
            {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(property));
            }

            if (!properties.Items.TryGetValue(property, out string value))
            {
                return null;
            }

            return value;
        }

        /// <summary>
        /// Sets the specified property in the authentication properties.
        /// </summary>
        /// <param name="properties">The authentication properties.</param>
        /// <param name="property">The property name.</param>
        /// <param name="value">The property value.</param>
        /// <returns>The <see cref="AuthenticationProperties"/> so that multiple calls can be chained.</returns>
        public static AuthenticationProperties SetProperty(
            [NotNull] this AuthenticationProperties properties,
            [NotNull] string property, [CanBeNull] string value)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            if (string.IsNullOrEmpty(property))
            {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(property));
            }

            if (string.IsNullOrEmpty(value))
            {
                properties.Items.Remove(property);
            }
            
            else
            {
                properties.Items[property] = value;
            }

            return properties;
        }
    }
}
