// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using NWebsec.Core.Extensions;
using NWebsec.Core.HttpHeaders;
using NWebsec.Core.HttpHeaders.Configuration;
using NWebsec.Middleware.Helpers;

namespace NWebsec.Middleware.Middleware
{
    public class CspMiddleware
    {
        private readonly ICspConfiguration _config;
        private readonly HeaderResult _headerResult;
        private readonly bool _reportOnly;
        private readonly RequestDelegate _next;

        public CspMiddleware(RequestDelegate next, ICspConfiguration options, bool reportOnly)
        {
            _next = next;
            _config = options;
            _reportOnly = reportOnly;

            var headerGenerator = new HeaderGenerator();
            _headerResult = headerGenerator.CreateCspResult(_config, reportOnly);
        }

        public async Task Invoke(HttpContext context)
        {

            if (HandleUpgradeInsecureRequest(context))
            {
                return;
            }

            SetCspHeaders(context);

            if (_next != null)
            {
                await _next(context);
            }

        }

        internal bool HandleUpgradeInsecureRequest(HttpContext context)
        {
            //Already on https.
            if (context.Request.IsHttps) return false;

            //CSP upgrade-insecure-requests is disabled
            if (!_config.Enabled || !_config.UpgradeInsecureRequestsDirective.Enabled) return false;

            if (!CspUpgradeHelper.UaSupportsUpgradeInsecureRequests(context)) return false;

            var upgradeUri = new UriBuilder($"https://{context.Request.Host}")
            {
                Port = _config.UpgradeInsecureRequestsDirective.HttpsPort,
                Path = context.Request.PathBase + context.Request.Path
            };

            //Redirect
            context.Response.Headers["Vary"] = "Upgrade-Insecure-Requests";
            context.Response.Headers["Location"] = upgradeUri.Uri.AbsoluteUri;
            context.Response.StatusCode = 307;
            return true;
        }

        internal void SetCspHeaders(HttpContext context)
        {
            if (_reportOnly)
            {
                context.GetNWebsecContext().CspReportOnly = _config;
            }
            else
            {
                context.GetNWebsecContext().Csp = _config;
            }

            if (_headerResult.Action == HeaderResult.ResponseAction.Set)
            {
                context.Response.Headers[_headerResult.Name] = _headerResult.Value;
            }
        }
    }
}