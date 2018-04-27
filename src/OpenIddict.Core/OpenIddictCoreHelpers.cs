using System;
using System.ComponentModel;
using System.Linq;
using System.Reflection;

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

            if (!definition.GetTypeInfo().IsGenericTypeDefinition)
            {
                throw new ArgumentException("The second parameter must be a generic type definition.", nameof(definition));
            }

            for (var candidate = type.GetTypeInfo(); candidate != null; candidate = candidate.BaseType?.GetTypeInfo())
            {
                if (!candidate.IsGenericType && !candidate.AsType().IsConstructedGenericType)
                {
                    continue;
                }

                if (candidate.GetGenericTypeDefinition() == definition)
                {
                    return candidate.AsType();
                }

                if (definition.GetTypeInfo().IsInterface)
                {
                    foreach (var contract in candidate.AsType().GetInterfaces().Select(contract => contract.GetTypeInfo()))
                    {
                        if (!contract.IsGenericType && !contract.AsType().IsConstructedGenericType)
                        {
                            continue;
                        }

                        if (contract.GetGenericTypeDefinition() == definition)
                        {
                            return contract.AsType();
                        }
                    }
                }
            }

            return null;
        }
    }
}
