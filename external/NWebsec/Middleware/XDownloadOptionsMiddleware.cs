// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using NWebsec.Core.Extensions;
using NWebsec.Core.HttpHeaders;
using NWebsec.Core.HttpHeaders.Configuration;

namespace NWebsec.Middleware.Middleware
{
    public class XDownloadOptionsMiddleware : MiddlewareBase
    {
        private readonly ISimpleBooleanConfiguration _config;
        private readonly HeaderResult _headerResult;

        public XDownloadOptionsMiddleware(RequestDelegate next)
            : base(next)
        {
            _config = new SimpleBooleanConfiguration { Enabled = true };
            var headerGenerator = new HeaderGenerator();
            _headerResult = headerGenerator.CreateXDownloadOptionsResult(_config);
        }

        internal override void PreInvokeNext(HttpContext owinEnvironment)
        {
            owinEnvironment.GetNWebsecContext().XDownloadOptions = _config;

            if (_headerResult.Action == HeaderResult.ResponseAction.Set)
            {
                owinEnvironment.Response.Headers[_headerResult.Name]= _headerResult.Value;
            }
        }
    }
}