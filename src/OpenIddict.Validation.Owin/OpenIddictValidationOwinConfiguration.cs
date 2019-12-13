/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.Extensions.Options;

namespace OpenIddict.Validation.Owin
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict validation configuration is valid.
    /// </summary>
    public class OpenIddictValidationOwinConfiguration : IConfigureOptions<OpenIddictValidationOptions>
    {
        public void Configure([NotNull] OpenIddictValidationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // Register the built-in event handlers used by the OpenIddict OWIN validation components.
            foreach (var handler in OpenIddictValidationOwinHandlers.DefaultHandlers)
            {
                options.DefaultHandlers.Add(handler);
            }
        }
    }
}
