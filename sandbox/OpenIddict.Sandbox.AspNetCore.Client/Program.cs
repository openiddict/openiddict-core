using Microsoft.AspNetCore;
using OpenIddict.Sandbox.AspNetCore.Client;
using OpenIddict.Sandbox.AspNetCore.Client.Models;

#if SUPPORTS_WEB_INTEGRATION_IN_GENERIC_HOST
var builder = Host.CreateDefaultBuilder(args);
builder.ConfigureWebHostDefaults(builder => builder.UseStartup<Startup>());
#else
var builder = WebHost.CreateDefaultBuilder(args);
builder.UseStartup<Startup>();
#endif

var app = builder.Build();

// Before starting the host, create the database used to store the application data.
//
// Note: in a real world application, this step should be part of a setup script.
await using (var scope = app.Services.CreateAsyncScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await context.Database.EnsureCreatedAsync();
}

await app.RunAsync();
