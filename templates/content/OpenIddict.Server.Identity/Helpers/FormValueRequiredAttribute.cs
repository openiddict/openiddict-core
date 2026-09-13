using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ActionConstraints;

namespace Company.Server.Helpers;

/// <summary>
/// Selects an action only when the request is a form POST containing the specified form value.
/// </summary>
public sealed class FormValueRequiredAttribute(string name) : ActionMethodSelectorAttribute
{
    public override bool IsValidForRequest(RouteContext routeContext, ActionDescriptor action)
    {
        var request = routeContext.HttpContext.Request;

        if (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method) ||
            HttpMethods.IsDelete(request.Method) || HttpMethods.IsTrace(request.Method))
        {
            return false;
        }

        if (string.IsNullOrEmpty(request.ContentType) ||
            !request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !string.IsNullOrEmpty(request.Form[name]);
    }
}
