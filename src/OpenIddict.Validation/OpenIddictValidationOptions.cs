/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OAuth.Validation;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict validation handler.
    /// </summary>
    public class OpenIddictValidationOptions : OAuthValidationOptions
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictValidationOptions"/> class.
        /// </summary>
        public OpenIddictValidationOptions()
        {
            Events = null;
            EventsType = typeof(OpenIddictValidationEvents);
        }

        /// <summary>
        /// Gets or sets the user-provided <see cref="OAuthValidationEvents"/> that the OpenIddict
        /// validation handler invokes to enable developer control over the entire authentication process.
        /// </summary>
        public OAuthValidationEvents ApplicationEvents { get; set; }

        /// <summary>
        /// Gets or sets the user-provided provider type that the OpenIddict validation handler
        /// instantiates to enable developer control over the entire authentication process. When this
        /// property is set, the provider is resolved from the services container. If the provider is not
        /// guaranteed to be thread-safe, registering it as a scoped dependency is strongly recommended.
        /// </summary>
        public Type ApplicationEventsType { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether reference tokens are used.
        /// </summary>
        public bool UseReferenceTokens { get; set; }
    }
}
