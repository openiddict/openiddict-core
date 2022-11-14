/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.WebIntegration;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict client Web integration configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed partial class OpenIddictClientWebIntegrationConfiguration : IConfigureOptions<OpenIddictClientOptions>
{
    /// <summary>
    /// Populates the default OpenIddict client Web integration options
    /// and ensures that the configuration is in a consistent and valid state.
    /// </summary>
    /// <param name="options">The options instance to initialize.</param>
    public void Configure(OpenIddictClientOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Register the built-in event handlers used by the OpenIddict client Web components.
        options.Handlers.AddRange(OpenIddictClientWebIntegrationHandlers.DefaultHandlers);
    }
}
