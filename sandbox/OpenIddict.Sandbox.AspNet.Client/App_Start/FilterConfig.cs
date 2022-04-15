using System.Web;
using System.Web.Mvc;

namespace OpenIddict.Sandbox.AspNet.Client
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
