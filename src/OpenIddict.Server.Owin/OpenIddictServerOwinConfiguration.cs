/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Text;
using JetBrains.Annotations;
using Microsoft.Extensions.Options;
using Microsoft.Owin.Security;

namespace OpenIddict.Server.Owin
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict server configuration is valid.
    /// </summary>
    public class OpenIddictServerOwinConfiguration : IConfigureNamedOptions<OpenIddictServerOptions>,
                                                     IPostConfigureOptions<OpenIddictServerOwinOptions>
    {
        public void Configure([NotNull] OpenIddictServerOptions options)
            => Debug.Fail("This infrastructure method shouldn't be called");

        public void Configure([CanBeNull] string name, [NotNull] OpenIddictServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // Register the built-in event handlers used by the OpenIddict OWIN server components.
            foreach (var handler in OpenIddictServerOwinHandlers.DefaultHandlers)
            {
                options.DefaultHandlers.Add(handler);
            }
        }

        public void PostConfigure([CanBeNull] string name, [NotNull] OpenIddictServerOwinOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (options.AuthenticationMode == AuthenticationMode.Active)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The OpenIddict OWIN server handler cannot be used as an active authentication handler.")
                    .Append("Make sure that 'OpenIddictServerOwinOptions.AuthenticationMode' is not set to 'Active'.")
                    .ToString());
            }
        }
    }
}
