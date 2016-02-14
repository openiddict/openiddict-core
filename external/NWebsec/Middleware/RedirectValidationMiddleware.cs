// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using NWebsec.Core;

namespace NWebsec.Middleware.Middleware
{

    public class RedirectValidationMiddleware : MiddlewareBase
    {
        private readonly RedirectValidationOptions _config;
        private readonly RedirectValidator _redirectValidator;

        public RedirectValidationMiddleware(RequestDelegate next, RedirectValidationOptions options)
            : base(next)
        {
            _config = options;
            _redirectValidator = new RedirectValidator();
        }

        internal override void PostInvokeNext(HttpContext context)
        {
            var statusCode = context.Response.StatusCode;

            if (!_redirectValidator.IsRedirectStatusCode(statusCode))
            {
                return;
            }

            var scheme = context.Request.Scheme;
            var hostandport = context.Request.Host;
            var requestUri = new Uri(scheme + "://" + hostandport);
            
            _redirectValidator.ValidateRedirect(statusCode, context.Response.Headers["Location"], requestUri, _config);
        }
    }
}