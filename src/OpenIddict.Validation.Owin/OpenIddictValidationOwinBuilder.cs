/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using JetBrains.Annotations;
using Microsoft.Owin.Security;
using OpenIddict.Validation.Owin;
using SR = OpenIddict.Abstractions.Resources.OpenIddictResources;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes the necessary methods required to configure
    /// the OpenIddict validation OWIN/Katana integration.
    /// </summary>
    public class OpenIddictValidationOwinBuilder
    {
        /// <summary>
        /// Initializes a new instance of <see cref="OpenIddictValidationOwinBuilder"/>.
        /// </summary>
        /// <param name="services">The services collection.</param>
        public OpenIddictValidationOwinBuilder([NotNull] IServiceCollection services)
            => Services = services ?? throw new ArgumentNullException(nameof(services));

        /// <summary>
        /// Gets the services collection.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IServiceCollection Services { get; }

        /// <summary>
        /// Amends the default OpenIddict validation OWIN/Katana configuration.
        /// </summary>
        /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictValidationOwinBuilder"/>.</returns>
        public OpenIddictValidationOwinBuilder Configure([NotNull] Action<OpenIddictValidationOwinOptions> configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            Services.Configure(configuration);

            return this;
        }

        /// <summary>
        /// Configures the OpenIddict validation OWIN integration to use active authentication.
        /// When using active authentication, the principal resolved from the access token is
        /// attached to the request context and 401/403 responses are automatically handled without
        /// requiring an explicit call to <see cref="AuthenticationManager.Challenge(string[])"/>.
        /// </summary>
        /// <remarks>
        /// Using active authentication is strongly discouraged in applications using a cookie
        /// authentication middleware configured to use active authentication, as both middleware
        /// will be invoked when handling 401 responses, which will result in invalid responses.
        /// </remarks>
        /// <returns>The <see cref="OpenIddictValidationOwinBuilder"/>.</returns>
        public OpenIddictValidationOwinBuilder UseActiveAuthentication()
            => Configure(options => options.AuthenticationMode = AuthenticationMode.Active);

        /// <summary>
        /// Sets the realm returned to the caller as part of the WWW-Authenticate header.
        /// </summary>
        /// <param name="realm">The issuer address.</param>
        /// <returns>The <see cref="OpenIddictValidationOwinBuilder"/>.</returns>
        public OpenIddictValidationOwinBuilder SetRealm([NotNull] string realm)
        {
            if (string.IsNullOrEmpty(realm))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1106), nameof(realm));
            }

            return Configure(options => options.Realm = realm);
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="obj">The object to compare with the current object.</param>
        /// <returns><c>true</c> if the specified object is equal to the current object; otherwise, false.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([CanBeNull] object obj) => base.Equals(obj);

        /// <summary>
        /// Serves as the default hash function.
        /// </summary>
        /// <returns>A hash code for the current object.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => base.GetHashCode();

        /// <summary>
        /// Returns a string that represents the current object.
        /// </summary>
        /// <returns>A string that represents the current object.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string ToString() => base.ToString();
    }
}
