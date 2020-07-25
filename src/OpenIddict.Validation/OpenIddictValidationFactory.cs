/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace OpenIddict.Validation
{
    public class OpenIddictValidationFactory : IOpenIddictValidationFactory
    {
        private readonly IStringLocalizer<OpenIddictResources> _localizer;
        private readonly ILogger<OpenIddictValidationDispatcher> _logger;
        private readonly IOptionsMonitor<OpenIddictValidationOptions> _options;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictValidationFactory"/> class.
        /// </summary>
        public OpenIddictValidationFactory(
            [NotNull] IStringLocalizer<OpenIddictResources> localizer,
            [NotNull] ILogger<OpenIddictValidationDispatcher> logger,
            [NotNull] IOptionsMonitor<OpenIddictValidationOptions> options)
        {
            _localizer = localizer;
            _logger = logger;
            _options = options;
        }

        public ValueTask<OpenIddictValidationTransaction> CreateTransactionAsync()
            => new ValueTask<OpenIddictValidationTransaction>(new OpenIddictValidationTransaction
            {
                Issuer = _options.CurrentValue.Issuer,
                Localizer = _localizer,
                Logger = _logger,
                Options = _options.CurrentValue
            });
    }
}
