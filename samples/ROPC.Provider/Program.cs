namespace Application
{
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore.Infrastructure;
    using Application.Models;
    using OpenIddict.Models;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Logging;
    using System.Linq;

    public class Program
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services
                .AddEntityFramework()
                .AddEntityFrameworkInMemoryDatabase()
                .AddDbContext<MyDbContext>(options =>
                {
                    options.UseInMemoryDatabase();
                });

            services
                .AddIdentity<MyUser, MyRole>()
                .AddEntityFrameworkStores<MyDbContext>()
                .AddDefaultTokenProviders()
                .AddOpenIddictCore<Application>(configuration =>
                {
                    // Use the EF adapter by default.
                    configuration.UseEntityFramework();
                });
        }

        public void Configure(
            IApplicationBuilder app,
            MyDbContext dbContext,
            UserManager<MyUser> userManager, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(LogLevel.Debug);
            
            #region Seed Database
                        
            dbContext.Database.EnsureCreated();
            if(!dbContext.Applications.Any())
            {
                dbContext.Applications.Add(new Application {
                    Id = "resource_server", 
                    DisplayName = "Resource Server", 
                    Secret = "875sqd4s5d748z78z7ds1ff8zz8814ff88ed8ea4z4zzd",
                    Type = OpenIddict.OpenIddictConstants.ApplicationTypes.Confidential,
                    RedirectUri = string.Empty, 
                    LogoutRedirectUri = string.Empty
                });
            }
                
            // test adding to a normal DbSet.
            dbContext.Sandboxes.Add(new Sandbox());
            dbContext.SaveChangesAsync().Wait();

            // seed a user
            var user = new MyUser { UserName = "test@test.com", Email = "test@test.com" };
            userManager.CreateAsync(user, "Testing123!").Wait();
            
            #endregion

            app.UseOpenIddictCore(builder =>
            {
                builder.Options.UseJwtTokens();
                builder.Options.AllowInsecureHttp = true;
                builder.Options.ApplicationCanDisplayErrors = true;
            });
        }

        public static void Main(string[] args)
        {
            var port = 5000;
            for (var i = 0; i < args.Length; ++i)
            {
                if (args[i] == "--port")
                {
                    int.TryParse(args[i + 1], out port);
                    break;
                }
            }

            var builder = new WebHostBuilder()
                .UseKestrel()
                .UseUrls($"http://localhost:{port}")
                .UseStartup<Program>()
                .Build();

            builder.Run();
        }
    }
}

namespace Application.Models
{
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore;
    using OpenIddict;

    public class MyDbContext : OpenIddictContext<MyUser>
    {
        public DbSet<Sandbox> Sandboxes { get; set; }
        public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
        {
        }
    }

    public class MyUser : IdentityUser
    {
    }

    public class MyRole : IdentityRole
    {
    }

    public class Sandbox
    {
        public int SandboxId { get; set; }
    }
}
