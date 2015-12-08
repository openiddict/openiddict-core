# OpenIddict
### The OpenID Connect server you'll be addicted to.

[![Build status](https://ci.appveyor.com/api/projects/status/d0d8git3o6lqkvbm?svg=true)](https://ci.appveyor.com/project/aspnet-contrib/core) 
[![Build status](https://travis-ci.org/openiddict/core.svg)](https://travis-ci.org/openiddict/core)


### What's OpenIddict?

OpenIddict aims at providing a **simple and easy-to-use solution** to implement an **OpenID Connect server in any ASP.NET 5 application**.


### Why an OpenID Connect server?

Adding an OpenID Connect server to your application **allows you to support token authentication**.
It also allows you to manage all your users using local password or an external identity provider
(e.g. Facebook or Google) for all your applications in one central place,
with the power to control who can access your API and the information that is exposed to each client.


### How does it work?

OpenIddict is based on **[ASP.NET Identity 3](https://github.com/aspnet/Identity)** (for user management) and relies on
**[AspNet.Security.OpenIdConnect.Server](https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server)** to control the OpenID Connect authentication flow. It comes with a built-in MVC 6 controller and native views that you can easily replace by your own ones to fully customize your login experience:

![](https://cloud.githubusercontent.com/assets/6998306/10988233/d9026712-843a-11e5-8ff0-e7addffd727b.png)

OpenIddict fully supports the **code/implicit/hybrid flows** and the **client credentials/resource owner password grants**. For more information about these terms, please visit the **[OpenID website](http://openid.net/specs/openid-connect-core-1_0.html)** and read the **[OAuth2 specification](https://tools.ietf.org/html/rfc6749)**.

Note: OpenIddict uses **[EntityFramework 7](https://github.com/aspnet/EntityFramework)** by default, but you can also provide your own store.

--------------

## Getting started

To use OpenIddict, you need to:

  - **Update your DNX runtime to use the latest RC2 nightly builds**:
```
dnvm upgrade -u
```

  - **Have an existing project or create a new one** (note: when creating a new project using Visual Studio's default ASP.NET 5 template, using **individual user accounts authentication** is strongly recommended).

  - **Add the appropriate MyGet repositories to your NuGet sources**. This can be done by adding a new `NuGet.Config` file at the root of your solution:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="aspnet-contrib" value="https://www.myget.org/F/aspnet-contrib/api/v2" />
    <add key="AspNetVNext" value="https://www.myget.org/F/aspnetvnext/api/v2" />
    <add key="AzureAd Nightly" value="http://www.myget.org/F/azureadwebstacknightly/" />
    <add key="NuGet" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
```

  - **Update your `project.json`** to import the `OpenIddict` package:

```json
"dependencies": {
    "OpenIddict": "1.0.0-*"
},
```

  - **Configure the OpenIddict services** in `Startup.ConfigureServices`:

```csharp
public void ConfigureServices(IServiceCollection services) {
    services.AddMvc();

    services.AddEntityFramework()
        .AddSqlServer()
        .AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(Configuration["Data:DefaultConnection:ConnectionString"]));

    services.AddIdentity<ApplicationUser, IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders()
        .AddOpenIddict(); // Add the OpenIddict services after registering the Identity services.
}
```

  - **Add the OpenIddict middleware in your ASP.NET 5 pipeline** by calling `app.UseOpenIddict()` after `app.UseIdentity()`:

```csharp
public void Configure(IApplicationBuilder app) {
    app.UseIdentity();
    
    // Add all the external providers you need before registering OpenIddict:
    app.UseGoogleAuthentication();
    app.UseFacebookAuthentication();
    
    app.UseOpenIddict();
}
```

> **Note:** `UseOpenIddict()` must be registered ***after*** `app.UseIdentity()` and the external providers.

For a better insight on the different options and configurations available, check out 
[Configuration and Options](https://github.com/openiddict/core/wiki/Configuration-&-Options)
in the project wiki.

## Support

**Need help or wanna share your thoughts? Don't hesitate to join our dedicated chat rooms:**

- **JabbR: [https://jabbr.net/#/rooms/aspnet-contrib](https://jabbr.net/#/rooms/aspnet-contrib)**
- **Gitter: [https://gitter.im/openiddict/core](https://gitter.im/openiddict/core)**

## Contributors

**OpenIddict** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
