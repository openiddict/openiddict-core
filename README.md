# OpenIddict
### The OpenID Connect server you'll be addicted to.

[![Build status](https://ci.appveyor.com/api/projects/status/46ofo2eusje0hcw2/branch/dev?svg=true)](https://ci.appveyor.com/project/openiddict/openiddict-core/branch/dev)
[![Build status](https://travis-ci.org/openiddict/openiddict-core.svg?branch=dev)](https://travis-ci.org/openiddict/openiddict-core)

> **Warning: this branch contains the OpenIddict 3.0 source code, which is still a work in progress. The 3.0.0 alpha packages haven't been heavily tested: don't use them in production**.
Nightly builds can be downloaded from the MyGet repository: https://www.myget.org/F/openiddict/api/v3/index.json

### Compatibility matrix

|                  | OpenIddict 1.0     | OpenIddict 2.0     | OpenIddict 2.0.1   | OpenIddict 3.0 (alpha) |
|------------------|--------------------|--------------------|--------------------|------------------------|
| ASP.NET Core 1.x | :heavy_check_mark: | :x:                | :x:                | :x:                    |
| ASP.NET Core 2.x | :x:                | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark:     |
| ASP.NET Core 3.x | :x:                | :warning:          | :heavy_check_mark: | :heavy_check_mark:     |
| ASP.NET 4.x/OWIN | :x:                | :x:                | :x:                | :heavy_check_mark:     |

### What's OpenIddict?

OpenIddict aims at providing an **easy-to-use and versatile solution** to implement an **OpenID Connect server in any ASP.NET Core 2.x or 3.x application**,
and **starting in OpenIddict 3.0, any ASP.NET 4.x or OWIN application too**.

OpenIddict fully supports the **[code/implicit/hybrid flows](http://openid.net/specs/openid-connect-core-1_0.html)**, the **[client credentials/resource owner password grants](https://tools.ietf.org/html/rfc6749)** and the [device authorization flow](https://tools.ietf.org/html/rfc8628). You can also create your own custom grant types.

OpenIddict natively supports **[Entity Framework Core](https://www.nuget.org/packages/OpenIddict.EntityFrameworkCore)**, **[Entity Framework 6](https://www.nuget.org/packages/OpenIddict.EntityFramework)** and **[MongoDB](https://www.nuget.org/packages/OpenIddict.MongoDb)** out-of-the-box, but you can also provide your own stores.

### Why an OpenID Connect server?

Adding an OpenID Connect server to your application **allows you to support token authentication**.
It also allows you to manage all your users using local password or an external identity provider
(e.g. Facebook or Google) for all your applications in one central place,
with the power to control who can access your API and the information that is exposed to each client.

## Documentation

**The documentation for the latest stable release (2.x) can be found in the [dedicated repository](https://openiddict.github.io/openiddict-documentation)**.

## Samples

**[Specialized samples for the latest stable release can be found in the samples repository](https://github.com/openiddict/openiddict-samples):**

  - [Authorization code flow sample](https://github.com/openiddict/openiddict-samples/tree/dev/samples/CodeFlow)
  - [Implicit flow sample](https://github.com/openiddict/openiddict-samples/tree/dev/samples/ImplicitFlow)
  - [Password flow sample](https://github.com/openiddict/openiddict-samples/tree/dev/samples/PasswordFlow)
  - [Client credentials flow sample](https://github.com/openiddict/openiddict-samples/tree/dev/samples/ClientCredentialsFlow)
  - [Refresh flow sample](https://github.com/openiddict/openiddict-samples/tree/dev/samples/RefreshFlow)

--------------

## Getting started

To use OpenIddict 3.x, you need to:

  - **Install the latest [.NET Core 3.x tooling](https://www.microsoft.com/net/download)**.

  - **Have an existing project or create a new one**: when creating a new project using Visual Studio's default ASP.NET Core template, using **individual user accounts authentication** is strongly recommended. When updating an existing project, you must provide your own `AccountController` to handle the registration process and the authentication flow.

  - **Create a `NuGet.config` file referencing the OpenIddict feed** (at the root of your solution):

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="nuget" value="https://api.nuget.org/v3/index.json" />
    <add key="openiddict" value="https://www.myget.org/F/openiddict/api/v3/index.json" />
  </packageSources>
</configuration>
```

  - **Update your `.csproj` file** to reference the `OpenIddict` packages:

```xml
<PackageReference Include="OpenIddict.AspNetCore" Version="3.0.0-*" />
<PackageReference Include="OpenIddict.EntityFrameworkCore" Version="3.0.0-*" />
```

  - **Configure the OpenIddict core, server and validation services** in `Startup.ConfigureServices`:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddOpenIddict()

        // Register the OpenIddict core components.
        .AddCore(options =>
        {
            // Configure OpenIddict to use the Entity Framework Core stores and models.
            options.UseEntityFrameworkCore()
                   .UseDbContext<ApplicationDbContext>();
        })

        // Register the OpenIddict server components.
        .AddServer(options =>
        {
            // Enable the token endpoint (required to use the password flow).
            options.SetTokenEndpointUris("/connect/token");

            // Allow client applications to use the grant_type=password flow.
            options.AllowPasswordFlow();

            // Accept requests sent by unknown clients (i.e that don't send a client_id).
            // When this option is not used, a client registration must be
            // created for each client using IOpenIddictApplicationManager.
            options.AcceptAnonymousClients();

            // Register the signing and encryption credentials.
            options.AddDevelopmentEncryptionCertificate()
                   .AddDevelopmentSigningCertificate();

            // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
            options.UseAspNetCore()
                   .EnableTokenEndpointPassthrough()
                   .DisableTransportSecurityRequirement(); // During development, you can disable the HTTPS requirement.
        })

        // Register the OpenIddict validation components.
        .AddValidation(options =>
        {
            // Import the configuration from the local OpenIddict server instance.
            options.UseLocalServer();

            // Register the ASP.NET Core host.
            options.UseAspNetCore();
        });
}
```

> **Note:** for more information about the different options and configurations available, check out 
[the documentation](https://openiddict.github.io/openiddict-documentation/configuration/index.html).

  - **Make sure the authentication middleware is registered before the other middleware, including `app.UseEndpoints()`**:

```csharp
public void Configure(IApplicationBuilder app)
{
    app.UseRouting();

    app.UseAuthentication();
    app.UseAuthorization();

    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");
        endpoints.MapRazorPages();
    });
}
```

  - **Update your Entity Framework Core context registration to register the OpenIddict entities**:

```csharp
services.AddDbContext<ApplicationDbContext>(options =>
{
    // Configure the context to use Microsoft SQL Server.
    options.UseSqlServer(Configuration["Data:DefaultConnection:ConnectionString"]);

    // Register the entity sets needed by OpenIddict.
    // Note: use the generic overload if you need
    // to replace the default OpenIddict entities.
    options.UseOpenIddict();
});
```

> **Note:** if you change the default entity primary key (e.g. to `int` or `Guid` instead of `string`), make sure you use the `options.ReplaceDefaultEntities<TKey>()` core extension accepting a `TKey` generic argument and use the generic `options.UseOpenIddict<TKey>()` overload to configure Entity Framework Core to use the specified key type:


```csharp
services.AddOpenIddict()
    .AddCore(options =>
    {
        // Configure OpenIddict to use the default entities with a custom key type.
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>()
               .ReplaceDefaultEntities<Guid>();
    });

services.AddDbContext<ApplicationDbContext>(options =>
{
    // Configure the context to use Microsoft SQL Server.
    options.UseSqlServer(configuration["Data:DefaultConnection:ConnectionString"]);

    options.UseOpenIddict<Guid>();
});
```

  - **Create your own authorization controller**:

To **support the password or the client credentials flow, you must provide your own token endpoint action**.
To enable authorization code/implicit flows support, you'll similarly have to create your own authorization endpoint action and your own views/view models.

The **Mvc.Server sample comes with an [`AuthorizationController` that supports both the password flow and the authorization code flow and that you can easily reuse in your application](https://github.com/openiddict/openiddict-core/blob/dev/samples/Mvc.Server/Controllers/AuthorizationController.cs)**.

## Resources

**Looking for additional resources to help you get started?** Don't miss these interesting blog posts/books:

- **[Setting up ASP.NET v5 (vNext) to use JWT tokens (using OpenIddict)](http://capesean.co.za/blog/asp-net-5-jwt-tokens/)** by [Sean Walsh](https://github.com/capesean/)
- **[Using OpenIddict to easily add token authentication to your .NET web apps](http://overengineer.net/Using-OpenIddict-to-easily-add-token-authentication-to-your-.NET-web-apps)** by [Josh Comley](https://github.com/joshcomley)
- **[Authorizing your .NET Core MVC6 API requests with OpenIddict and Identity](http://kerryritter.com/authorizing-your-net-core-mvc6-api-requests-with-openiddict-and-identity/)** by [Kerry Ritter](https://github.com/kerryritter)
- **[Creating your own OpenID Connect server with ASOS](http://kevinchalet.com/2016/07/13/creating-your-own-openid-connect-server-with-asos-introduction/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Bearer Token Authentication in ASP.NET Core](https://blogs.msdn.microsoft.com/webdev/2016/10/27/bearer-token-authentication-in-asp-net-core/)** by [Mike Rousos](https://github.com/mjrousos) (for the Microsoft .NET Web Development and Tools blog)
- **[ASP.NET Core and Angular 2](https://www.amazon.com/ASP-NET-Core-Angular-Valerio-Sanctis-ebook/dp/B01DZQHCVU/)** by [Valerio De Sanctis](https://github.com/Darkseal)
- **[Implementing simple token authentication in ASP.NET Core with OpenIddict](http://kevinchalet.com/2017/01/30/implementing-simple-token-authentication-in-aspnet-core-with-openiddict/)** by [Kévin Chalet](https://github.com/kevinchalet)

## Support

**Need help or wanna share your thoughts?** Don't hesitate to join us on Gitter or ask your question on StackOverflow:

- **Gitter: [https://gitter.im/openiddict/openiddict-core](https://gitter.im/openiddict/openiddict-core)**
- **StackOverflow: [https://stackoverflow.com/questions/tagged/openiddict](https://stackoverflow.com/questions/tagged/openiddict)**

## Contributors

**OpenIddict** is actively maintained by **[Kévin Chalet](https://github.com/kevinchalet)**. Contributions are welcome and can be submitted using pull requests.

**Special thanks to the following sponsors for their incredible support**:

- [David Hamilton](https://github.com/daveh101) from [DAM Good Media](https://www.damgoodmedia.com/)
- [Christopher McCrum](https://github.com/chrisjmccrum) from [Data Citadel](http://www.datacitadel.com/)

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
