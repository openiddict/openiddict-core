namespace Application
{
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore.Infrastructure;
    using Application.Models;
    using OpenIddict.Models;

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

        public void Configure(IApplicationBuilder app, MyDbContext dbContext)
        {
            // test adding to a normal DbSet.
            dbContext.Sandboxes.Add(new Sandbox());
            dbContext.SaveChangesAsync();

            app.UseOpenIddictCore(builder =>
            {
                builder.Options.UseJwtTokens();
                builder.Options.AllowInsecureHttp = true;
                builder.Options.ApplicationCanDisplayErrors = true;
            });
        }

        public static void Main(string[] args)
        {
            var builder = new WebHostBuilder()
                .UseKestrel()
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
