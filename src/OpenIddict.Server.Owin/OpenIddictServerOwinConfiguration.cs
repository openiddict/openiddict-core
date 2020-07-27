/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.Options;
using Microsoft.Owin.Security;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.Owin
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict server configuration is valid.
    /// </summary>
    public class OpenIddictServerOwinConfiguration : IConfigureOptions<OpenIddictServerOptions>,
                                                     IPostConfigureOptions<OpenIddictServerOwinOptions>
    {
        public void Configure(OpenIddictServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // Register the built-in event handlers used by the OpenIddict OWIN server components.
            options.Handlers.AddRange(OpenIddictServerOwinHandlers.DefaultHandlers);
        }

        public void PostConfigure(string name, OpenIddictServerOwinOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (options.AuthenticationMode == AuthenticationMode.Active)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1118));
            }
        }
    }
}
