/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server
{
    public class OpenIddictServerFactory : IOpenIddictServerFactory
    {
        private readonly ILogger<OpenIddictServerDispatcher> _logger;
        private readonly IOptionsMonitor<OpenIddictServerOptions> _options;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictServerDispatcher"/> class.
        /// </summary>
        public OpenIddictServerFactory(
            [NotNull] ILogger<OpenIddictServerDispatcher> logger,
            [NotNull] IOptionsMonitor<OpenIddictServerOptions> options)
        {
            _logger = logger;
            _options = options;
        }

        public ValueTask<OpenIddictServerTransaction> CreateTransactionAsync()
            => new ValueTask<OpenIddictServerTransaction>(new OpenIddictServerTransaction
            {
                Issuer = _options.CurrentValue.Issuer,
                Logger = _logger,
                Options = _options.CurrentValue
            });
    }
}
