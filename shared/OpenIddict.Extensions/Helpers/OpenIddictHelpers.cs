using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace OpenIddict.Extensions
{
    /// <summary>
    /// Exposes common helpers used by the OpenIddict assemblies.
    /// </summary>
    internal static class OpenIddictHelpers
    {
        /// <summary>
        /// Finds the first base type that matches the specified generic type definition.
        /// </summary>
        /// <param name="type">The type to introspect.</param>
        /// <param name="definition">The generic type definition.</param>
        /// <returns>A <see cref="Type"/> instance if the base type was found, <c>null</c> otherwise.</returns>
        public static Type FindGenericBaseType(Type type, Type definition)
            => FindGenericBaseTypes(type, definition).FirstOrDefault();

        /// <summary>
        /// Finds all the base types that matches the specified generic type definition.
        /// </summary>
        /// <param name="type">The type to introspect.</param>
        /// <param name="definition">The generic type definition.</param>
        /// <returns>A <see cref="Type"/> instance if the base type was found, <c>null</c> otherwise.</returns>
        public static IEnumerable<Type> FindGenericBaseTypes(Type type, Type definition)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (definition == null)
            {
                throw new ArgumentNullException(nameof(definition));
            }

            if (!definition.GetTypeInfo().IsGenericTypeDefinition)
            {
                throw new ArgumentException("The second parameter must be a generic type definition.", nameof(definition));
            }

            if (definition.GetTypeInfo().IsInterface)
            {
                foreach (var contract in type.GetInterfaces())
                {
                    if (!contract.GetTypeInfo().IsGenericType && !contract.IsConstructedGenericType)
                    {
                        continue;
                    }

                    if (contract.GetGenericTypeDefinition() == definition)
                    {
                        yield return contract;
                    }
                }
            }

            else
            {
                for (var candidate = type; candidate != null; candidate = candidate.GetTypeInfo().BaseType)
                {
                    if (!candidate.GetTypeInfo().IsGenericType && !candidate.IsConstructedGenericType)
                    {
                        continue;
                    }

                    if (candidate.GetGenericTypeDefinition() == definition)
                    {
                        yield return candidate;
                    }
                }
            }
        }
    }
}
