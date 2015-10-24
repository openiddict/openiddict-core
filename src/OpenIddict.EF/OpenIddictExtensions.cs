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
using Microsoft.Data.Entity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using OpenIddict;

namespace Microsoft.AspNet.Builder {
    public static class OpenIddictExtensions {
        public static OpenIddictBuilder AddEntityFrameworkStore([NotNull] this OpenIddictBuilder builder) {
            builder.Services.AddScoped(
                typeof(IOpenIddictStore<,>).MakeGenericType(builder.UserType, builder.ApplicationType),
                typeof(OpenIddictStore<,,,,>).MakeGenericType(
                    /* TUser: */ builder.UserType,
                    /* TApplication: */ builder.ApplicationType,
                    /* TRole: */ builder.RoleType,
                    /* TContext: */ ResolveContextType(builder),
                    /* TKey: */ ResolveKeyType(builder)));

            return builder;
        }

        private static Type ResolveContextType([NotNull] OpenIddictBuilder builder) {
            var service = (from registration in builder.Services
                           where registration.ServiceType.IsConstructedGenericType
                           let definition = registration.ServiceType.GetGenericTypeDefinition()
                           where definition == typeof(IUserStore<>)
                           select registration.ImplementationType).SingleOrDefault();

            if (service == null) {
                throw new InvalidOperationException(
                    "The type of the database context cannot be automatically inferred. " +
                    "Make sure 'AddOpenIddict()' is the last chained call when configuring the services.");
            }

            TypeInfo type;
            for (type = service.GetTypeInfo(); type != null; type = type.BaseType?.GetTypeInfo()) {
                if (!type.IsGenericType) {
                    continue;
                }

                var definition = type.GetGenericTypeDefinition();
                if (definition == null) {
                    continue;
                }

                if (definition != typeof(UserStore<,,,>)) {
                    continue;
                }

                return (from argument in type.AsType().GetGenericArguments()
                        where typeof(DbContext).IsAssignableFrom(argument)
                        select argument).Single();
            }

            throw new InvalidOperationException("The type of the database context cannot be automatically inferred.");
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