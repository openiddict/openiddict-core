/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using OpenIddict.Extensions;
using OpenIddict.Validation;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes the necessary methods required to configure the OpenIddict validation services.
    /// </summary>
    public class OpenIddictValidationBuilder
    {
        /// <summary>
        /// Initializes a new instance of <see cref="OpenIddictValidationBuilder"/>.
        /// </summary>
        /// <param name="services">The services collection.</param>
        public OpenIddictValidationBuilder([NotNull] IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            Services = services;
        }

        /// <summary>
        /// Gets the services collection.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IServiceCollection Services { get; }

        /// <summary>
        /// Registers an inline event handler for the specified event type.
        /// </summary>
        /// <param name="handler">The handler delegate.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictValidationBuilder AddEventHandler<TEvent>(
            [NotNull] Func<TEvent, Task<OpenIddictValidationEventState>> handler)
            where TEvent : class, IOpenIddictValidationEvent
        {
            if (handler == null)
            {
                throw new ArgumentNullException(nameof(handler));
            }

            Services.AddSingleton<IOpenIddictValidationEventHandler<TEvent>>(
                new OpenIddictValidationEventHandler<TEvent>(handler));

            return this;
        }

        /// <summary>
        /// Registers an event handler that will be invoked for all the events listed by the implemented interfaces.
        /// </summary>
        /// <typeparam name="THandler">The type of the handler.</typeparam>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictValidationBuilder AddEventHandler<THandler>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
            => AddEventHandler(typeof(THandler), lifetime);

        /// <summary>
        /// Registers an event handler that will be invoked for all the events listed by the implemented interfaces.
        /// </summary>
        /// <param name="type">The type of the handler.</param>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictValidationBuilder AddEventHandler([NotNull] Type type, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (lifetime == ServiceLifetime.Transient)
            {
                throw new ArgumentException("Handlers cannot be registered as transient services.", nameof(lifetime));
            }

            if (type.IsGenericTypeDefinition)
            {
                throw new ArgumentException("The specified type is invalid.", nameof(type));
            }

            var services = OpenIddictHelpers.FindGenericBaseTypes(type, typeof(IOpenIddictValidationEventHandler<>)).ToArray();
            if (services.Length == 0)
            {
                throw new ArgumentException("The specified type is invalid.", nameof(type));
            }

            foreach (var service in services)
            {
                Services.Add(new ServiceDescriptor(service, type, lifetime));
            }

            return this;
        }

        /// <summary>
        /// Amends the default OpenIddict validation configuration.
        /// </summary>
        /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder Configure([NotNull] Action<OpenIddictValidationOptions> configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            Services.Configure(OpenIddictValidationDefaults.AuthenticationScheme, configuration);

            return this;
        }

        /// <summary>
        /// Registers the specified values as valid audiences. Setting the audiences is recommended
        /// when the authorization server issues access tokens for multiple distinct resource servers.
        /// </summary>
        /// <param name="audiences">The audiences valid for this resource server.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddAudiences([NotNull] params string[] audiences)
        {
            if (audiences == null)
            {
                throw new ArgumentNullException(nameof(audiences));
            }

            if (audiences.Any(audience => string.IsNullOrEmpty(audience)))
            {
                throw new ArgumentException("Audiences cannot be null or empty.", nameof(audiences));
            }

            return Configure(options => options.Audiences.UnionWith(audiences));
        }

        /// <summary>
        /// Enables authorization validation so that a database call is made for each API request
        /// to ensure the authorization associated with the access token is still valid.
        /// Note: enabling this option may have an impact on performance.
        /// </summary>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder EnableAuthorizationValidation()
            => Configure(options => options.EnableAuthorizationValidation = true);

        /// <summary>
        /// Configures OpenIddict not to return the authentication error
        /// details as part of the standard WWW-Authenticate response header.
        /// </summary>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder RemoveErrorDetails()
            => Configure(options => options.IncludeErrorDetails = false);

        /// <summary>
        /// Sets the realm, which is used to compute the WWW-Authenticate response header.
        /// </summary>
        /// <param name="realm">The realm.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder SetRealm([NotNull] string realm)
        {
            if (string.IsNullOrEmpty(realm))
            {
                throw new ArgumentException("The realm cannot be null or empty.", nameof(realm));
            }

            return Configure(options => options.Realm = realm);
        }

        /// <summary>
        /// Configures OpenIddict to use a specific data protection provider
        /// instead of relying on the default instance provided by the DI container.
        /// </summary>
        /// <param name="provider">The data protection provider used to create token protectors.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder UseDataProtectionProvider([NotNull] IDataProtectionProvider provider)
        {
            if (provider == null)
            {
                throw new ArgumentNullException(nameof(provider));
            }

            return Configure(options => options.DataProtectionProvider = provider);
        }

        /// <summary>
        /// Configures the OpenIddict validation handler to use reference tokens.
        /// </summary>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder UseReferenceTokens()
            => Configure(options => options.UseReferenceTokens = true);
    }
}
