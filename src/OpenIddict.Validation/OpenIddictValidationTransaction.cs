/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Represents the context associated with an OpenID Connect validation request.
    /// </summary>
    public class OpenIddictValidationTransaction
    {
        /// <summary>
        /// Gets or sets the type of the endpoint processing the current request.
        /// </summary>
        public OpenIddictValidationEndpointType EndpointType { get; set; }

        /// <summary>
        /// Gets or sets the issuer address associated with the current transaction, if available.
        /// </summary>
        public Uri Issuer { get; set; }

        /// <summary>
        /// Gets or sets the localizer associated with the current request.
        /// </summary>
        public IStringLocalizer Localizer { get; set; }

        /// <summary>
        /// Gets or sets the logger associated with the current request.
        /// </summary>
        public ILogger Logger { get; set; }

        /// <summary>
        /// Gets or sets the options associated with the current request.
        /// </summary>
        public OpenIddictValidationOptions Options { get; set; }

        /// <summary>
        /// Gets the additional properties associated with the current request.
        /// </summary>
        public IDictionary<string, object> Properties { get; }
            = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Gets or sets the current OpenID Connect request.
        /// </summary>
        public OpenIddictRequest Request { get; set; }

        /// <summary>
        /// Gets or sets the current OpenID Connect response being returned.
        /// </summary>
        public OpenIddictResponse Response { get; set; }
    }
}
