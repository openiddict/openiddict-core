/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;

namespace OpenIddict.Client.Maui;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict client configuration is valid.
/// </summary>
public class OpenIddictClientMauiConfiguration : IConfigureOptions<OpenIddictClientOptions>
{
    public void Configure(OpenIddictClientOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Register the built-in event handlers used by the OpenIddict MAUI client components.
        options.Handlers.AddRange(OpenIddictClientMauiHandlers.DefaultHandlers);
    }
}
