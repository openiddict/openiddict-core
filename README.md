# OpenIddict, as an OpenID Connect Addict

### What's OpenIddict ?

OpenIddict library aims to provide a simple and easy out of the box solution 
to implement an OpenID Connect server for ASP.NET 5.

It leverages the use of Identity (for user management) and 
EntityFramework (as a store provider).

Under the hood it uses [AspNet.Security.OpenIdConnect.Server](https://github.com/PinpointTownes/AspNet.Security.OpenIdConnect.Server) 
middleware that works with any standards-compliant OAuth 2.0/OpenID Connect 
client including the official OpenID Connect client middleware 
developed by Microsoft.

### What's OpenID Connect ?

Applications often need to identify their users. 
The simplistic approach is to create a local database for the users’ accounts 
and credentials. While this may work well for some scenarios, people find
signup and account creation to be tedious which translates to less users using
your application.

Having multiple applications; maintainance of user databases and 
registration/login workflows can easily became an administrative and 
security nightmare.

The established solution to these problems is to delegate user authentication 
and provisioning to a dedicated, purpose-built service, called an Identity 
Provider (IdP).

OpenID Connect is a standard protocol on top of OAuth 2.0 that enables Clients to 
verify the identity of the End-User based on the authentication performed by 
an Authorization Server, as well as to obtain basic profile information about 
the End-User in an interoperable and REST-like manner.

For more documentation, visit [OpenID Connect web site](http://openid.net/connect/)

### Why an OpenID Connect Server?

A consumer web site can greatly streamline user onboarding by integrating 
login with existing Identity Providers.
On the enterprise side, this would be ideally be one internal Identity Provider.

Having an internal Idenity Provider provides you ability to use local password 
authentication, control the information that is exposed to the client applications
and more generally, you can control who access your API.

In general terms, you may want to have a centralized authentication for many
clients (yours or not) that handle identity.

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

In `ConfigureServices` there's a handy extension method of `IdentityBuilder` 
that you need to set up. Here is a complete `ConfigureServices` including 
Identity, Mvc and EntityFramework:

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

in the `Configure` method, you configure your pipeline to use it:

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

### Configuration & Options.

OpenIddict have multiple options you can set to customize for your 
requirements/needs.

<table>
<thead>
    <tr><th>Options</th><th>type</th><th>Description</th><th>Default</th></tr>
</thead>
<tbody>
<tr>
<td>AuthenticationScheme</td>
<td>string</td>
<td>
    The base address used to uniquely identify the authorization server.<br>
    The URI must be absolute and may contain a path, but no query string or fragment part.<br>
    Unless <code>AllowInsecureHttp</code> has been set to <code>true</code>, an HTTPS address must be provided.
</td>
<td><code>oidc-server</code></td>
</tr>
<tr>
  <td>Issuer</td>
  <td>Uri</td>
  <td>The base address (absolute) used to uniquely identify the authorization server.<br>
      <sub><i>Unless <code>AllowInsecureHttp</code> has been set to <code>true</code>, an HTTPS address must be provided.</i></sub>
  </td>
  <td>Automatically inferred from the request URL</td>
</tr>
<tr>
  <td>
    AuthorizationEndpointPath
    <br>
    LogoutEndpointPath
  </td>
  <td>PathString</td>
  <td>The path of the endpoint. Can be set to <code>PathString.Empty</code> to disable the endpoint.</td>
  <td>
      <code>/connect/authorize</code>
      <br>
      <code>/connect/logout</code>
  </td>
      
</tr>
<tr>
  <td>
    AuthorizationCodeLifetime
    <br>
    AccessTokenLifetime
    <br>
    IdentityTokenLifetime
    <br>
    RefreshTokenLifetime
  </td>
  <td>TimeSpan</td>
  <td>The period of time the token or code remains valid after being issued.</td>
  <td>
    5 minutes
    <br>
    1 hour
    <br>
    20 minutes
    <br>
    6 hours
  </td>
</tr>
<tr>
  <td>UseSlidingExpiration</td>
  <td>bool</td>
  <td>
    Determines whether refresh tokens issued during a <code>grant_type=refresh_token</code> request should be generated with a new expiration date or should re-use the same expiration date as the original refresh token.
    <br>
    <sub>Set this property to <code>true</code> to assign a new expiration date each time a refresh token is issued, <code>false</code> to use the expiration date of the original refresh token.</sub>
  </td>
  <td><code>true</code></td>
</tr>
<tr>
  <td>ApplicationCanDisplayErrors</td>
  <td>bool</td>
  <td>Set to <code>true</code> if the web application is able to render error messages on the authorization endpoint.</td>
  <td><code>false</code></td>
</tr>
<tr>
  <td>AllowInsecureHttp</td>
  <td>bool</td>
  <td>
    Set to <code>true</code> to allow incoming requests to arrive on HTTP and to allow `redirect_uri` parameters to have HTTP URI addresses.
    <br>
    <sub>Setting this option to <code>false</code> in production is strongly encouraged to mitigate man-in-the-middle attacks.</sub>
  </td>
  <td><code>false</code></td>
</tr>
</tbody>
</table>

## Support

**Need help or wanna share your thoughts? Don't hesitate to join our dedicated chat rooms:**

- **JabbR: [https://jabbr.net/#/rooms/aspnet-contrib](https://jabbr.net/#/rooms/aspnet-contrib)**

## Contributors

**OpenIddict** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
