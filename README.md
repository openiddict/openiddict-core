OpenIddict<br><sub>The OpenID Connect server you'll be addict to.</sub>
=======

AppVeyor: [![Build status](https://ci.appveyor.com/api/projects/status/d0d8git3o6lqkvbm?svg=true)](https://ci.appveyor.com/project/aspnet-contrib/core)

Travis: [![Build status](https://travis-ci.org/openiddict/core.svg)](https://travis-ci.org/openiddict/core)

### What's OpenIddict ?

OpenIddict aims at providing a simple and easy out of the box solution 
to implement an OpenID Connect server for ASP.NET 5.


### Why an OpenID Connect Server?

With an OpenID Connect Server you can manage all your users using local 
password or an external identity provider management for all your applications 
in one central place, with the power to control who can access your API and 
the information that is exposed to each client. 


### How does it work?

OpenIddict, by default, leverages the use of Identity (for user management) and 
EntityFramework (as an optional store provider).

Adding it to your existing application allows you to register clients and 
serve them authenticate tokens.

Under the hood it uses [AspNet.Security.OpenIdConnect.Server](https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server) 
middleware that works with any standards-compliant OAuth 2.0/OpenID Connect 
client including the official OpenID Connect client middleware 
developed by Microsoft.

--------------

## Getting Started

You can find working samples in the [samples](https://github.com/openiddict/core/tree/dev/samples) directory.

Nightly builds can now be found on the [aspnet-contrib](https://github.com/aspnet-contrib) MyGet repository https://www.myget.org/F/aspnet-contrib/api/v3/index.json.

To use OpenIddict Server you need to include OpenIddict as a dependency in your project.json:

```json
"dependencies": {
    "OpenIddict": "1.0.0-*"
},
```

There's a handy extension method of `IdentityBuilder` to add the services needed
to the dependency container in your `ConfigureServices` method. Here is a 
complete `ConfigureServices` including Identity, Mvc and EntityFramework:

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
        .AddOpenIddict();

    /// .... other services you may have
}
```

To configure your pipeline, there's also a handy extension method to plug the
`OpenIddict` middleware into it you can use on `Configure` method: 

```csharp
public void Configure(IApplicationBuilder app) {
    app.UseIdentity();
    
    // any external provider like, app.UseGoogleAuthentication, app.UseFacebookAuthentication, etc..
    
    app.UseOpenIddict(options => {
        // options
    });
}
```

> **Note:** `UseOpenIddict()` must be used ***after*** `app.UseIdentity()` and any external providers.

For a better insight in different options and configurations available check out 
[Configuration & Options](https://github.com/openiddict/core/wiki/Configuration-&-Options)
in the project wiki.

## Support

**Need help or wanna share your thoughts? Don't hesitate to join our dedicated chat rooms:**

- **JabbR: [https://jabbr.net/#/rooms/aspnet-contrib](https://jabbr.net/#/rooms/aspnet-contrib)**

## Contributors

**OpenIddict** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
