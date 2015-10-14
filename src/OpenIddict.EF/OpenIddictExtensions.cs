/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Reflection;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using OpenIddict;

namespace Microsoft.AspNet.Builder {
    public static class OpenIddictExtensions {
        public static OpenIddictBuilder AddEntityFrameworkStore([NotNull] this OpenIddictBuilder builder) {
            // Resolve the key type from the user type definition.
            var keyType = ResolveKeyType(builder);

            builder.Services.AddScoped(
                typeof(IOpenIddictStore<,>).MakeGenericType(builder.UserType, builder.ApplicationType),
                typeof(OpenIddictStore<,,,>).MakeGenericType(builder.UserType, builder.ApplicationType, builder.RoleType, keyType));
            
            var type = typeof(OpenIddictContext<,,,>).MakeGenericType(new[] {
                /* TUser: */ builder.UserType,
                /* TApplication: */ builder.ApplicationType,
                /* TRole: */ builder.RoleType,
                /* TKey: */ keyType
            });

            builder.Services.AddScoped(type, provider => {
                // Resolve the user store from the parent container and extract the associated context.
                dynamic store = provider.GetRequiredService(typeof(IUserStore<>).MakeGenericType(builder.UserType));

                dynamic context = store?.Context;
                if (!type.GetTypeInfo().IsAssignableFrom(context?.GetType())) {
                    throw new InvalidOperationException(
                        "Only EntityFramework contexts derived from " +
                        "OpenIddictContext can be used with OpenIddict.");
                }

                return context;
            });

            return builder;
        }

        private static Type ResolveKeyType([NotNull] OpenIddictBuilder builder) {
            TypeInfo type;
            for (type = builder.UserType.GetTypeInfo(); type != null; type = type.BaseType?.GetTypeInfo()) {
                if (!type.IsGenericType) {
                    continue;
                }

                var definition = type.GetGenericTypeDefinition();
                if (definition == null) {
                    continue;
                }

                if (definition != typeof(IdentityUser<>)) {
                    continue;
                }

                return type.AsType().GetGenericArguments().Single();
            }

            throw new InvalidOperationException(
                "The type of the key identifier used by the user " +
               $"entity '{builder.UserType}' cannot be automatically inferred.");
        }
    }
}