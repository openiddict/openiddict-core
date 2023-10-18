/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.Options;

namespace OpenIddict.Pruning.BackgroundService;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict Quartz.NET configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictPruningConfiguration : IConfigureOptions<OpenIddictPruningOptions>
{
    /// <inheritdoc/>
    public void Configure(OpenIddictPruningOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        //SR.GetResourceString(SR.ID8002)
    }
}
