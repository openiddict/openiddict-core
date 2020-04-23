/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace OpenIddict.Validation.AspNetCore
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict validation configuration is valid.
    /// </summary>
    public class OpenIddictValidationAspNetCoreConfiguration : IConfigureOptions<AuthenticationOptions>,
                                                               IConfigureOptions<OpenIddictValidationOptions>,
                                                               IPostConfigureOptions<AuthenticationOptions>
    {
        /// <summary>
        /// Registers the OpenIddict validation handler in the global authentication options.
        /// </summary>
        /// <param name="options">The options instance to initialize.</param>
        public void Configure([NotNull] AuthenticationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // If a handler was already registered and the type doesn't correspond to the OpenIddict handler, throw an exception.
            if (options.SchemeMap.TryGetValue(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, out var builder) &&
                builder.HandlerType != typeof(OpenIddictValidationAspNetCoreHandler))
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The OpenIddict ASP.NET Core validation handler cannot be registered as an authentication scheme.")
                    .Append("This may indicate that an instance of another handler was registered with the same scheme.")
                    .ToString());
            }

            options.AddScheme<OpenIddictValidationAspNetCoreHandler>(
                OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, displayName: null);
        }

        public void Configure([NotNull] OpenIddictValidationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // Register the built-in event handlers used by the OpenIddict ASP.NET Core validation components.
            foreach (var handler in OpenIddictValidationAspNetCoreHandlers.DefaultHandlers)
            {
                options.DefaultHandlers.Add(handler);
            }
        }

        /// <summary>
        /// Ensures that the authentication configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The name of the options instance to configure, if applicable.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([CanBeNull] string name, [NotNull] AuthenticationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            bool TryValidate(string scheme)
            {
                // If the scheme was not set or if it cannot be found in the map, return true.
                if (string.IsNullOrEmpty(scheme) || !options.SchemeMap.TryGetValue(scheme, out var builder))
                {
                    return true;
                }

                return builder.HandlerType != typeof(OpenIddictValidationAspNetCoreHandler);
            }

            if (!TryValidate(options.DefaultSignInScheme) || !TryValidate(options.DefaultSignOutScheme))
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The OpenIddict ASP.NET Core validation cannot be used as the default sign-in/sign-out handler.")
                    .Append("Make sure that neither DefaultSignInScheme nor DefaultSignOutScheme ")
                    .Append("point to an instance of the OpenIddict ASP.NET Core validation handler.")
                    .ToString());
            }
        }
    }
}
