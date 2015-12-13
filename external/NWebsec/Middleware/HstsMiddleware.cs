// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using NWebsec.Core.HttpHeaders;
using NWebsec.Core.HttpHeaders.Configuration;
using NWebsec.Middleware.Helpers;

namespace NWebsec.Middleware.Middleware
{

    public class HstsMiddleware : MiddlewareBase
    {
        private readonly IHstsConfiguration _config;
        private readonly HeaderResult _headerResult;
        private const string Https = "https";

        public HstsMiddleware(RequestDelegate next, HstsOptions options)
            : base(next)
        {
            _config = options;

            var headerGenerator = new HeaderGenerator();
            _headerResult = headerGenerator.CreateHstsResult(_config);
        }

        internal override void PreInvokeNext(HttpContext context)
        {

            if (_config.HttpsOnly && !context.Request.IsHttps)
            {
                return;
            }

            if (_config.UpgradeInsecureRequests && !CspUpgradeHelper.UaSupportsUpgradeInsecureRequests(context))
            {
                return;
            }
            
            if (_headerResult.Action == HeaderResult.ResponseAction.Set)
            {
                context.Response.Headers[_headerResult.Name] = _headerResult.Value;
            }
        }
    }
}