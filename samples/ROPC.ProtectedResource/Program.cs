using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;

namespace Application
{
    public class Program
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            services.AddMvcCore()
                    .AddJsonFormatters();

            services.AddAuthentication();
            services.AddDistributedMemoryCache();
        }

        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(LogLevel.Debug);

            app.UseOAuthIntrospection(options =>
            {
                options.AutomaticAuthenticate = true;
                options.AutomaticChallenge = true;
                options.Authority = "http://localhost:5001/";
                options.ClientId = "resource_server";
                options.ClientSecret = "secret_secret_secret";
            });

            app.UseMvc();
        }

        public static void Main(string[] args)
        {
            var host = new WebHostBuilder()
                        .UseKestrel()
                        .UseUrls($"http://localhost:5002")
                        .UseStartup<Program>()
                        .Build();

            host.Run();
        }
    }
}
