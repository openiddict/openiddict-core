/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Primitives;

namespace OpenIddict.Mvc
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict MVC integration.
    /// </summary>
    public class OpenIddictMvcOptions
    {
        /// <summary>
        /// Gets or sets a boolean indicating whether the OpenIddict MVC binder should throw
        /// an exception when it is unable to bind <see cref="OpenIdConnectRequest"/>
        /// parameters (e.g because the endpoint is not an OpenID Connect endpoint).
        /// If exceptions are disabled, the model is automatically set to <c>null</c>.
        /// </summary>
        public bool DisableBindingExceptions { get; set; }
    }
}
