using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using AspNet.Security.OAuth.Introspection;
using Microsoft.AspNetCore.Http;
using System.Text;

namespace Application
{
    [Route("api/simple")]
    public class SimpleController
    {
        IHttpContextAccessor _httpContextAccessor;
        public SimpleController(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        [Authorize(ActiveAuthenticationSchemes = OAuthIntrospectionDefaults.AuthenticationScheme)]
        public ActionResult Get()
        {
            var identity = _httpContextAccessor
                .HttpContext
                .User
                .Identity;
                
            var builder = new StringBuilder();
            builder.AppendLine($"Name: {identity.Name}");
            builder.AppendLine($"IsAuthenticated: {identity.IsAuthenticated}");
            
            return new ContentResult
            {
                Content = builder.ToString() 
            };
        }
    }
}