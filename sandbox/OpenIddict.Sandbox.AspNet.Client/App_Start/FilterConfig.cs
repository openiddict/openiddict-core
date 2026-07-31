using System.Web.Mvc;

namespace OpenIddict.Sandbox.AspNet.Client;

public static class FilterConfig
{
    public static void RegisterGlobalFilters(GlobalFilterCollection filters)
    {
        filters.Add(new HandleErrorAttribute());
    }
}
