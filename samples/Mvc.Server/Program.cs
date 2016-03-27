using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace Mvc.Server {
    public static class Program {
        public static void Main(string[] args) {
            var host = new WebHostBuilder()
                .ConfigureLogging(options => options.AddConsole())
                .ConfigureLogging(options => options.AddDebug())
                .UseDefaultHostingConfiguration(args)
                .UseIISPlatformHandlerUrl()
                .UseServer("Microsoft.AspNetCore.Server.Kestrel")
                .UseStartup<Startup>()
                .Build();

            host.Run();
        }
    }
}
