using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using OpenIddict.Tests.Infrastructure;

namespace OpenIddict.Tests
{
    public abstract class BaseHostedTests
    {
        protected async Task UseTestHost(Func<HttpClient, Task> invokeAction)
        {
            var webHostBuilder = new WebHostBuilder()
                .UseStartup<Startup>();

            using (var host = new TestServer(webHostBuilder))
            {
                using (var client = host.CreateClient())
                {
                    await invokeAction.Invoke(client);
                }
            }
        }
    }
}