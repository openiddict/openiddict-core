// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using NWebsec.Core.Extensions;
using NWebsec.Core.HttpHeaders;
using NWebsec.Core.HttpHeaders.Configuration;

namespace NWebsec.Middleware.Middleware
{

    public class XRobotsTagMiddleware : MiddlewareBase
    {
        private readonly IXRobotsTagConfiguration _config;
        private readonly HeaderResult _headerResult;

        public XRobotsTagMiddleware(RequestDelegate next, XRobotsTagOptions options)
            : base(next)
        {
            _config = options.Config;

            var headerGenerator = new HeaderGenerator();
            _headerResult = headerGenerator.CreateXRobotsTagResult(_config);
        }

        internal override void PreInvokeNext(HttpContext owinEnvironment)
        {
            owinEnvironment.GetNWebsecContext().XRobotsTag = _config;

            if (_headerResult.Action == HeaderResult.ResponseAction.Set)
            {
                owinEnvironment.Response.Headers[_headerResult.Name] = _headerResult.Value;
            }
        }
    }
}