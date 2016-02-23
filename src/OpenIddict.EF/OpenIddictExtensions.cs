/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Reflection;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict;
using OpenIddict.Models;

namespace Microsoft.AspNetCore.Builder {
    public static class OpenIddictExtensions {
        public static OpenIddictConfiguration UseEntityFramework([NotNull] this OpenIddictConfiguration configuration) {
            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            if (!IsSubclassOf(configuration.ApplicationType, typeof(Application<>))) {
                throw new InvalidOperationException("The default store cannot be used with application " +
                                                    "entities that are not derived from Application<TKey>.");
            }

            configuration.Services.AddScoped(
                typeof(IOpenIddictStore<,>).MakeGenericType(configuration.UserType, configuration.ApplicationType),
                typeof(OpenIddictStore<,,,>).MakeGenericType(
                    /* TUser: */ configuration.UserType,
                    /* TApplication: */ configuration.ApplicationType,
                    /* TContext: */ ResolveContextType(configuration),
                    /* TKey: */ ResolveKeyType(configuration)));

            return configuration;
        }

        private static Type ResolveContextType([NotNull] OpenIddictConfiguration configuration) {
            var service = (from registration in configuration.Services
                           where registration.ServiceType.IsConstructedGenericType
                           let definition = registration.ServiceType.GetGenericTypeDefinition()
                           where definition == typeof(IUserStore<>)
                           select registration.ImplementationType).FirstOrDefault();

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

        private static Type ResolveKeyType([NotNull] OpenIddictConfiguration configuration) {
            TypeInfo type;
            for (type = configuration.UserType.GetTypeInfo(); type != null; type = type.BaseType?.GetTypeInfo()) {
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
               $"entity '{configuration.UserType}' cannot be automatically inferred.");
        }

        private static bool IsSubclassOf([NotNull] Type type, [NotNull] Type generic) {
            while (type != null && type != typeof(object)) {
                var current = type.GetTypeInfo().IsGenericType ?
                    type.GetGenericTypeDefinition() :
                    type;

                if (current == generic) {
                    return true;
                }

                type = type.GetTypeInfo().BaseType;
            }

            return false;
        }
    }
}