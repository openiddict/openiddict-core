using System;
using System.Reflection;
using System.Web.Mvc;

namespace OpenIddict.Sandbox.AspNet.Server.Helpers
{
    public sealed class FormValueRequiredAttribute : ActionMethodSelectorAttribute
    {
        private readonly string _name;

        public FormValueRequiredAttribute(string name)
        {
            _name = name;
        }

        public override bool IsValidForRequest(ControllerContext controllerContext, MethodInfo methodInfo)
        {
            if (string.Equals(controllerContext.HttpContext.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(controllerContext.HttpContext.Request.HttpMethod, "HEAD", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(controllerContext.HttpContext.Request.HttpMethod, "DELETE", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(controllerContext.HttpContext.Request.HttpMethod, "TRACE", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (string.IsNullOrEmpty(controllerContext.HttpContext.Request.ContentType))
            {
                return false;
            }

            if (!controllerContext.HttpContext.Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return !string.IsNullOrEmpty(controllerContext.HttpContext.Request.Form[_name]);
        }
    }
}
