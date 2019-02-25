# OpenIddict
### The OpenID Connect server you'll be addicted to.

[![Build status](https://ci.appveyor.com/api/projects/status/46ofo2eusje0hcw2?svg=true)](https://ci.appveyor.com/project/openiddict/openiddict-core)
[![Build status](https://travis-ci.org/openiddict/openiddict-core.svg)](https://travis-ci.org/openiddict/openiddict-core)

> **Warning: this branch contains the OpenIddict 3.0 source code, which is still a work in progress. The 3.0 packages are still experimental and no official binaries are available yet**.
**These packages currently lack many features and haven't been heavily tested: don't use them in any production application**.

### What's OpenIddict?

OpenIddict aims at providing a **simple and easy-to-use solution** to implement an **OpenID Connect server in any ASP.NET Core 1.x or 2.x application**.

OpenIddict is based on
**[AspNet.Security.OpenIdConnect.Server (codenamed ASOS)](https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server)** to control the OpenID Connect authentication flow and can be used with any membership stack, **including [ASP.NET Core Identity](https://github.com/aspnet/Identity)**.

OpenIddict fully supports the **[code/implicit/hybrid flows](http://openid.net/specs/openid-connect-core-1_0.html)** and the **[client credentials/resource owner password grants](https://tools.ietf.org/html/rfc6749)**. You can also create your own custom grant types.

Note: OpenIddict natively supports **[Entity Framework Core](https://www.nuget.org/packages/OpenIddict.EntityFrameworkCore)**, **[Entity Framework 6](https://www.nuget.org/packages/OpenIddict.EntityFramework)** and **[MongoDB](https://www.nuget.org/packages/OpenIddict.MongoDb)** out-of-the-box, but you can also provide your own stores.

> Note: **the OpenIddict 2.x packages are only compatible with ASP.NET Core 2.x**.
> If your application targets ASP.NET Core 1.x, use the OpenIddict 1.x packages.

### Why an OpenID Connect server?

Adding an OpenID Connect server to your application **allows you to support token authentication**.
It also allows you to manage all your users using local password or an external identity provider
(e.g. Facebook or Google) for all your applications in one central place,
with the power to control who can access your API and the information that is exposed to each client.

## Documentation

**The documentation can be found in the [dedicated repository](https://openiddict.github.io/openiddict-documentation)**.

## Samples

**[Specialized samples can be found in the samples repository](https://github.com/openiddict/openiddict-samples):**

  - [Authorization code flow sample](https://github.com/openiddict/openiddict-samples/tree/dev/samples/CodeFlow)
  - [Implicit flow sample](https://github.com/openiddict/openiddict-samples/tree/dev/samples/ImplicitFlow)
  - [Password flow sample](https://github.com/openiddict/openiddict-samples/tree/dev/samples/PasswordFlow)
  - [Client credentials flow sample](https://github.com/openiddict/openiddict-samples/tree/dev/samples/ClientCredentialsFlow)
  - [Refresh flow sample](https://github.com/openiddict/openiddict-samples/tree/dev/samples/RefreshFlow)

> **Samples for ASP.NET Core 1.x can be found [in the master branch of the samples repository](https://github.com/openiddict/openiddict-samples/tree/master)**.
--------------

## Getting started

To use OpenIddict, you need to:

  - **Install the latest [.NET Core 2.x tooling](https://www.microsoft.com/net/download) and update your packages to reference the ASP.NET Core 2.x packages**.

  - **Have an existing project or create a new one**: when creating a new project using Visual Studio's default ASP.NET Core template, using **individual user accounts authentication** is strongly recommended. When updating an existing project, you must provide your own `AccountController` to handle the registration process and the authentication flow.

  - **Update your `.csproj` file** to reference the `OpenIddict` packages:

```xml
<PackageReference Include="OpenIddict" Version="2.0.0" />
<PackageReference Include="OpenIddict.EntityFrameworkCore" Version="2.0.0" />
```

  - **Configure the OpenIddict services** in `Startup.ConfigureServices`:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddMvc();

    services.AddDbContext<ApplicationDbContext>(options =>
    {
        // Configure the context to use Microsoft SQL Server.
        options.UseSqlServer(configuration["Data:DefaultConnection:ConnectionString"]);

        // Register the entity sets needed by OpenIddict.
        // Note: use the generic overload if you need
        // to replace the default OpenIddict entities.
        options.UseOpenIddict();
    });

    // Register the Identity services.
    services.AddIdentity<ApplicationUser, IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();

    // Register the OpenIddict services.
    services.AddOpenIddict()
        .AddCore(options =>
        {
            // Configure OpenIddict to use the Entity Framework Core stores and entities.
            options.UseEntityFrameworkCore()
                   .UseDbContext<ApplicationDbContext>();
        })

        .AddServer(options =>
        {
            // Register the ASP.NET Core MVC binder used by OpenIddict.
            // Note: if you don't call this method, you won't be able to
            // bind OpenIdConnectRequest or OpenIdConnectResponse parameters.
            options.UseMvc();

            // Enable the token endpoint (required to use the password flow).
            options.EnableTokenEndpoint("/connect/token");

            // Allow client applications to use the grant_type=password flow.
            options.AllowPasswordFlow();

            // During development, you can disable the HTTPS requirement.
            options.DisableHttpsRequirement();

            // Accept token requests that don't specify a client_id.
            options.AcceptAnonymousClients();
        })

        .AddValidation();
}
```

> **Note:** for more information about the different options and configurations available, check out 
[Configuration and options](https://github.com/openiddict/core/wiki/Configuration-and-options)
in the project wiki.

  - **Make sure the authentication middleware is registered before all the other middleware, including `app.UseMvc()`**:

```csharp
public void Configure(IApplicationBuilder app)
{
    app.UseAuthentication();

    app.UseMvc();
}
```

  - **Update your Entity Framework Core context registration to register the OpenIddict entities**:

```csharp
services.AddDbContext<ApplicationDbContext>(options =>
{
    // Configure the context to use Microsoft SQL Server.
    options.UseSqlServer(configuration["Data:DefaultConnection:ConnectionString"]);

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

  - **Enable the corresponding flows in the OpenIddict options**:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    // Register the OpenIddict services.
    services.AddOpenIddict()
        .AddCore(options =>
        {
            // Configure OpenIddict to use the Entity Framework Core stores and entities.
            options.UseEntityFrameworkCore()
                   .UseDbContext<ApplicationDbContext>();
        })

        .AddServer(options =>
        {
            // Register the ASP.NET Core MVC binder used by OpenIddict.
            // Note: if you don't call this method, you won't be able to
            // bind OpenIdConnectRequest or OpenIdConnectResponse parameters.
            options.UseMvc();

            // Enable the authorization and token endpoints (required to use the code flow).
            options.EnableAuthorizationEndpoint("/connect/authorize")
                   .EnableTokenEndpoint("/connect/token");

            // Allow client applications to use the code flow.
            options.AllowAuthorizationCodeFlow();

            // During development, you can disable the HTTPS requirement.
            options.DisableHttpsRequirement();
        })

        .AddValidation();
}
```

  - **Register your client application**:

```csharp
// Create a new service scope to ensure the database context is correctly disposed when this methods returns.
using (var scope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await context.Database.EnsureCreatedAsync();

    // Note: when using a custom entity or a custom key type, replace OpenIddictApplication by the appropriate type.
    var manager = scope.ServiceProvider.GetRequiredService<OpenIddictApplicationManager<OpenIddictApplication>>();

    if (await manager.FindByClientIdAsync("[client identifier]", cancellationToken) == null)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "[client identifier]",
            ClientSecret = "[client secret]",
            RedirectUris = { new Uri("[redirect uri]") }
        };

        await manager.CreateAsync(descriptor, cancellationToken);
    }
}
```

## Resources

**Looking for additional resources to help you get started?** Don't miss these interesting blog posts/books:

- **[Setting up ASP.NET v5 (vNext) to use JWT tokens (using OpenIddict)](http://capesean.co.za/blog/asp-net-5-jwt-tokens/)** by [Sean Walsh](https://github.com/capesean/)
- **[Using OpenIddict to easily add token authentication to your .NET web apps](http://overengineer.net/Using-OpenIddict-to-easily-add-token-authentication-to-your-.NET-web-apps)** by [Josh Comley](https://github.com/joshcomley)
- **[Authorizing your .NET Core MVC6 API requests with OpenIddict and Identity](http://kerryritter.com/authorizing-your-net-core-mvc6-api-requests-with-openiddict-and-identity/)** by [Kerry Ritter](https://github.com/kerryritter)
- **[Creating your own OpenID Connect server with ASOS](http://kevinchalet.com/2016/07/13/creating-your-own-openid-connect-server-with-asos-introduction/)** by [Kévin Chalet](https://github.com/PinpointTownes)
- **[Bearer Token Authentication in ASP.NET Core](https://blogs.msdn.microsoft.com/webdev/2016/10/27/bearer-token-authentication-in-asp-net-core/)** by [Mike Rousos](https://github.com/mjrousos) (for the Microsoft .NET Web Development and Tools blog)
- **[ASP.NET Core and Angular 2](https://www.amazon.com/ASP-NET-Core-Angular-Valerio-Sanctis-ebook/dp/B01DZQHCVU/)** by [Valerio De Sanctis](https://github.com/Darkseal)
- **[Implementing simple token authentication in ASP.NET Core with OpenIddict](http://kevinchalet.com/2017/01/30/implementing-simple-token-authentication-in-aspnet-core-with-openiddict/)** by [Kévin Chalet](https://github.com/PinpointTownes)

## Support

**Need help or wanna share your thoughts?** Don't hesitate to join us on Gitter or ask your question on StackOverflow:

- **Gitter: [https://gitter.im/openiddict/openiddict-core](https://gitter.im/openiddict/openiddict-core)**
- **StackOverflow: [https://stackoverflow.com/questions/tagged/openiddict](https://stackoverflow.com/questions/tagged/openiddict)**

## Contributors

**OpenIddict** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

**Special thanks to [Christopher McCrum](https://github.com/chrisjmccrum) and [Data Citadel](http://www.datacitadel.com/) for their incredible support**.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
