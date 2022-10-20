/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;

namespace OpenIddict.Client.Owin;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict client configuration is valid.
/// </summary>
public class OpenIddictClientOwinConfiguration : IConfigureOptions<OpenIddictClientOptions>,
                                                 IPostConfigureOptions<OpenIddictClientOwinOptions>
{
    public void Configure(OpenIddictClientOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Register the built-in event handlers used by the OpenIddict OWIN Client components.
        options.Handlers.AddRange(OpenIddictClientOwinHandlers.DefaultHandlers);
    }

    public void PostConfigure(string? name, OpenIddictClientOwinOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (options.AuthenticationMode is AuthenticationMode.Active)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0314));
        }
    }
}
