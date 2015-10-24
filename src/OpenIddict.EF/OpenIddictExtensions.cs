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
        public static OpenIddictServices UseEntityFramework([NotNull] this OpenIddictServices services) {
            services.Services.AddScoped(
                typeof(IOpenIddictStore<,>).MakeGenericType(services.UserType, services.ApplicationType),
                typeof(OpenIddictStore<,,,,>).MakeGenericType(
                    /* TUser: */ services.UserType,
                    /* TApplication: */ services.ApplicationType,
                    /* TRole: */ services.RoleType,
                    /* TContext: */ ResolveContextType(services),
                    /* TKey: */ ResolveKeyType(services)));

            return services;
        }

        private static Type ResolveContextType([NotNull] OpenIddictServices services) {
            var service = (from registration in services.Services
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

        private static Type ResolveKeyType([NotNull] OpenIddictServices services) {
            TypeInfo type;
            for (type = services.UserType.GetTypeInfo(); type != null; type = type.BaseType?.GetTypeInfo()) {
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
               $"entity '{services.UserType}' cannot be automatically inferred.");
        }
    }
}