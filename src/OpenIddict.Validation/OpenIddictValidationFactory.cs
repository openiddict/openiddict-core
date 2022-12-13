/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Validation;

/// <summary>
/// Represents a service responsible for creating transactions.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictValidationFactory : IOpenIddictValidationFactory
{
    private readonly ILogger<OpenIddictValidationDispatcher> _logger;
    private readonly IOptionsMonitor<OpenIddictValidationOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictValidationFactory"/> class.
    /// </summary>
    public OpenIddictValidationFactory(
        ILogger<OpenIddictValidationDispatcher> logger,
        IOptionsMonitor<OpenIddictValidationOptions> options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc/>
    public ValueTask<OpenIddictValidationTransaction> CreateTransactionAsync()
        => new(new OpenIddictValidationTransaction
        {
            Logger = _logger,
            Options = _options.CurrentValue
        });
}
