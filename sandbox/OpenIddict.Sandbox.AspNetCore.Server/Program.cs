using Microsoft.AspNetCore;

namespace OpenIddict.Sandbox.AspNetCore.Server;

public static class Program
{
#if SUPPORTS_WEB_INTEGRATION_IN_GENERIC_HOST
    public static void Main(string[] args) =>
        CreateHostBuilder(args).Build().Run();

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(builder => builder.UseStartup<Startup>());
#else
    public static void Main(string[] args) =>
        CreateWebHostBuilder(args).Build().Run();

    public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
        WebHost.CreateDefaultBuilder(args)
               .UseStartup<Startup>();
#endif
}
