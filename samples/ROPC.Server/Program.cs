namespace Application
{
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore.Infrastructure;
    using Application.Database;

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
        }

        public void Configure(IApplicationBuilder builder, MyDbContext dbContext)
        {
            // dbContext.Sandboxes.Add(new Sandbox());
            // dbContext.SaveChangesAsync();
            
            builder.Run(context =>
            {
                return context.Response.WriteAsync("Hello.");
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

namespace Application.Database
{
    using Microsoft.EntityFrameworkCore;

    public class MyDbContext : DbContext
    {
        public DbSet<Sandbox> Sandboxes { get; set; }

        public MyDbContext()
        { }

        public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
        {
        }
    }

    public class Sandbox
    {
        public int SandboxId { get; set; }
    }
}
