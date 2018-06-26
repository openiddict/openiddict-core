/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using OpenIddict.Abstractions;
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
        /// Registers an event handler for the specified event type.
        /// </summary>
        /// <param name="handler">The handler added to the DI container.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictValidationBuilder AddEventHandler<TEvent>(
            [NotNull] IOpenIddictValidationEventHandler<TEvent> handler)
            where TEvent : class, IOpenIddictValidationEvent
        {
            if (handler == null)
            {
                throw new ArgumentNullException(nameof(handler));
            }

            Services.AddSingleton(handler);

            return this;
        }

        /// <summary>
        /// Registers an event handler for the specified event type.
        /// </summary>
        /// <param name="handler">The handler added to the DI container.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictValidationBuilder AddEventHandler<TEvent>([NotNull] Func<TEvent, Task> handler)
            where TEvent : class, IOpenIddictValidationEvent
            => AddEventHandler<TEvent>((notification, cancellationToken) => handler(notification));

        /// <summary>
        /// Registers an event handler for the specified event type.
        /// </summary>
        /// <param name="handler">The handler added to the DI container.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictValidationBuilder AddEventHandler<TEvent>([NotNull] Func<TEvent, CancellationToken, Task> handler)
            where TEvent : class, IOpenIddictValidationEvent
        {
            if (handler == null)
            {
                throw new ArgumentNullException(nameof(handler));
            }

            return AddEventHandler(new OpenIddictValidationEventHandler<TEvent>(handler));
        }

        /// <summary>
        /// Registers an event handler for the specified event type.
        /// </summary>
        /// <typeparam name="TEvent">The type of the event.</typeparam>
        /// <typeparam name="THandler">The type of the handler.</typeparam>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictValidationBuilder AddEventHandler<TEvent, THandler>(
            ServiceLifetime lifetime = ServiceLifetime.Scoped)
            where TEvent : class, IOpenIddictValidationEvent
            where THandler : IOpenIddictValidationEventHandler<TEvent>
            => AddEventHandler<TEvent>(typeof(THandler));

        /// <summary>
        /// Registers an event handler for the specified event type.
        /// </summary>
        /// <param name="type">The type of the handler.</param>
        /// <param name="lifetime">The lifetime of the registered service.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictValidationBuilder AddEventHandler<TEvent>(
            [NotNull] Type type, ServiceLifetime lifetime = ServiceLifetime.Scoped)
            where TEvent : class, IOpenIddictValidationEvent
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (lifetime == ServiceLifetime.Transient)
            {
                throw new ArgumentException("Handlers cannot be registered as transient services.", nameof(lifetime));
            }

            if (!typeof(IOpenIddictValidationEventHandler<TEvent>).IsAssignableFrom(type))
            {
                throw new ArgumentException("The specified type is invalid.", nameof(type));
            }

            Services.Add(new ServiceDescriptor(typeof(IOpenIddictValidationEventHandler<TEvent>), type, lifetime));

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
