/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Net;
using System.Net.Http;
using Polly;
using Polly.Extensions.Http;

namespace OpenIddict.Validation.SystemNetHttp
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict validation/System.Net.Http integration.
    /// </summary>
    public class OpenIddictValidationSystemNetHttpOptions
    {
        /// <summary>
        /// Gets or sets the HTTP Polly error policy used by the internal OpenIddict HTTP clients.
        /// </summary>
        public IAsyncPolicy<HttpResponseMessage> HttpErrorPolicy { get; set; }
            = HttpPolicyExtensions.HandleTransientHttpError()
                .OrResult(response => response.StatusCode == HttpStatusCode.NotFound)
                .WaitAndRetryAsync(4, attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt)));
    }
}
