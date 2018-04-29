using System;
using System.ComponentModel;

namespace OpenIddict.Core
{
    /// <summary>
    /// Exposes common helpers used by the OpenIddict assemblies.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static class OpenIddictCoreHelpers
    {
        /// <summary>
        /// Finds the base type that matches the specified generic type definition.
        /// </summary>
        /// <param name="type">The type to introspect.</param>
        /// <param name="definition">The generic type definition.</param>
        /// <returns>A <see cref="Type"/> instance if the base type was found, <c>null</c> otherwise.</returns>
        public static Type FindGenericBaseType(Type type, Type definition)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (definition == null)
            {
                throw new ArgumentNullException(nameof(definition));
            }

            if (!definition.IsGenericTypeDefinition)
            {
                throw new ArgumentException("The second parameter must be a generic type definition.", nameof(definition));
            }

            if (definition.IsInterface)
            {
                foreach (var contract in type.GetInterfaces())
                {
                    if (!contract.IsGenericType && !contract.IsConstructedGenericType)
                    {
                        continue;
                    }

                    if (contract.GetGenericTypeDefinition() == definition)
                    {
                        return contract;
                    }
                }
            }

            else
            {
                for (var candidate = type; candidate != null; candidate = candidate.BaseType)
                {
                    if (!candidate.IsGenericType && !candidate.IsConstructedGenericType)
                    {
                        continue;
                    }

                    if (candidate.GetGenericTypeDefinition() == definition)
                    {
                        return candidate;
                    }
                }
            }

            return null;
        }
    }
}
