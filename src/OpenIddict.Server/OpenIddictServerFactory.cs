/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server;

/// <summary>
/// Represents a service responsible for creating transactions.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictServerFactory : IOpenIddictServerFactory
{
    private readonly ILogger _logger;
    private readonly IOptionsMonitor<OpenIddictServerOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerDispatcher"/> class.
    /// </summary>
    public OpenIddictServerFactory(
        ILogger<OpenIddictServerDispatcher> logger,
        IOptionsMonitor<OpenIddictServerOptions> options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc/>
    public ValueTask<OpenIddictServerTransaction> CreateTransactionAsync()
        => new(new OpenIddictServerTransaction
        {
            Logger = _logger,
            Options = _options.CurrentValue
        });
}
