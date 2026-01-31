using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Sandbox.AspNetCore.CimdServer;
using OpenIddict.Sandbox.AspNetCore.CimdServer.Models;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls("https://localhost:7295");

builder.Services.AddControllers();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "openiddict-sandbox-aspnetcore-cimdserver.sqlite3")}");
    options.UseOpenIddict();
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("connect/authorize")
               .SetTokenEndpointUris("connect/token");

        options.AllowAuthorizationCodeFlow()
               .AllowPasswordFlow()
               .AllowRefreshTokenFlow();

        options.RequireProofKeyForCodeExchange();

        options.RegisterScopes("openid", "profile", "email", "offline_access");

        // Enable Client ID Metadata Document (CIMD) support.
        options.EnableClientIdMetadataDocumentSupport();

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        // Disable access token encryption so tokens can be inspected during development.
        options.DisableAccessTokenEncryption();

        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough();

        options.UseSystemNetHttp();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

builder.Services.AddHostedService<Worker>();

var app = builder.Build();

app.UseDeveloperExceptionPage();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Serve a CIMD metadata document for testing.
// The client_id URL is: https://localhost:7295/clients/cimd-test
app.MapGet("/clients/cimd-test", () => Results.Json(new
{
    client_id = "https://localhost:7295/clients/cimd-test",
    client_name = "CIMD Test Client",
    redirect_uris = new[] { "http://localhost/callback" },
    grant_types = new[] { "authorization_code", "refresh_token" },
    response_types = new[] { "code" },
    token_endpoint_auth_method = "none"
}));

Console.WriteLine("CIMD Server starting on https://localhost:7295");
app.Run();
