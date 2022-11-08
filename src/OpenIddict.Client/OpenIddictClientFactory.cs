/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client;

public sealed class OpenIddictClientFactory : IOpenIddictClientFactory
{
    private readonly ILogger<OpenIddictClientDispatcher> _logger;
    private readonly IOptionsMonitor<OpenIddictClientOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientFactory"/> class.
    /// </summary>
    public OpenIddictClientFactory(
        ILogger<OpenIddictClientDispatcher> logger,
        IOptionsMonitor<OpenIddictClientOptions> options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public ValueTask<OpenIddictClientTransaction> CreateTransactionAsync()
        => new(new OpenIddictClientTransaction
        {
            Logger = _logger,
            Options = _options.CurrentValue
        });
}
