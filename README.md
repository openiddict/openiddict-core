# OpenIddict
### The OpenID Connect stack you'll be addicted to.

[![Build status](https://github.com/openiddict/openiddict-core/workflows/build/badge.svg?branch=dev&event=push)](https://github.com/openiddict/openiddict-core/actions?query=workflow%3Abuild+branch%3Adev+event%3Apush)

## What's OpenIddict?

OpenIddict aims at providing a **versatile solution** to implement an **OpenID Connect server and token validation in any ASP.NET Core 2.1, 3.1 and 5.0 application**,
and starting in OpenIddict 3.0, **any ASP.NET 4.x or OWIN application too**.

OpenIddict fully supports the **[code/implicit/hybrid flows](http://openid.net/specs/openid-connect-core-1_0.html)**, the **[client credentials/resource owner password grants](https://tools.ietf.org/html/rfc6749)** and the [device authorization flow](https://tools.ietf.org/html/rfc8628). You can also create your own custom grant types.

OpenIddict natively supports **[Entity Framework Core](https://www.nuget.org/packages/OpenIddict.EntityFrameworkCore)**, **[Entity Framework 6](https://www.nuget.org/packages/OpenIddict.EntityFramework)** and **[MongoDB](https://www.nuget.org/packages/OpenIddict.MongoDb)** out-of-the-box, but you can also provide your own stores.

## I want something simple and easy to configure

**Developers looking for a simple and turnkey solution are strongly encouraged to use [OrchardCore and its OpenID module](https://docs.orchardcore.net/en/dev/docs/reference/modules/OpenId/)**,
which is based on OpenIddict, comes with sensible defaults and offers a built-in management GUI to easily register OpenID client applications.

## Getting started

**To implement a custom OpenID Connect server using OpenIddict, the simplest option is to clone one of the official samples** from the [openiddict-samples repository](https://github.com/openiddict/openiddict-samples):
  - **[Samples for OpenIddict 3.0 can be found in the samples repository](https://github.com/openiddict/openiddict-samples).**
  - [Samples for OpenIddict 2.0.1 can be found in the master branch of the samples repository](https://github.com/openiddict/openiddict-samples/tree/master).

## Documentation

**The documentation for the latest stable release (2.0.1) can be found in the [dedicated repository](https://openiddict.github.io/openiddict-documentation)**.

## Compatibility matrix

| Web framework version | .NET runtime version | OpenIddict 2.0                          | OpenIddict 2.0.1                        | OpenIddict 3.0                          |
|-----------------------|----------------------|-----------------------------------------|-----------------------------------------|-----------------------------------------|
| ASP.NET Core 2.1      | .NET Framework 4.6.1 | :heavy_check_mark: :information_source: | :heavy_check_mark: :information_source: | :heavy_check_mark: :information_source: |
| ASP.NET Core 2.1      | .NET Framework 4.7.2 | :heavy_check_mark:                      | :heavy_check_mark:                      | :heavy_check_mark:                      |
| ASP.NET Core 2.1      | .NET Framework 4.8   | :heavy_check_mark:                      | :heavy_check_mark:                      | :heavy_check_mark:                      |
| ASP.NET Core 2.1      | .NET Core 2.1        | :heavy_check_mark:                      | :heavy_check_mark:                      | :heavy_check_mark:                      |
|                       |                      |                                         |                                         |                                         |
| ASP.NET Core 3.1      | .NET Core 3.1        | :warning:                               | :heavy_check_mark:                      | :heavy_check_mark:                      |
|                       |                      |                                         |                                         |                                         |
| ASP.NET Core 5.0      | .NET 5.0             | :warning:                               | :heavy_check_mark:                      | :heavy_check_mark:                      |
|                       |                      |                                         |                                         |                                         |
| OWIN/Katana 4.1       | .NET Framework 4.6.1 | :x:                                     | :x:                                     | :heavy_check_mark: :information_source: |
| OWIN/Katana 4.1       | .NET Framework 4.7.2 | :x:                                     | :x:                                     | :heavy_check_mark:                      |
| OWIN/Katana 4.1       | .NET Framework 4.8   | :x:                                     | :x:                                     | :heavy_check_mark:                      |

:information_source: **Note: the following features are not available when targeting .NET Framework 4.6.1**:
 - X.509 development encryption/signing certificates: calling `AddDevelopmentEncryptionCertificate()` or `AddDevelopmentSigningCertificate()`
will result in a `PlatformNotSupportedException` being thrown at runtime if no valid development certificate can be found and a new one must be generated.
 - X.509 ECDSA signing certificates/keys: calling `AddSigningCertificate()` or `AddSigningKey()`
with an ECDSA certificate/key will always result in a `PlatformNotSupportedException` being thrown at runtime.

--------------

## Resources

**Looking for additional resources to help you get started with 3.0?** Don't miss these interesting blog posts:

- **[Introducing Quartz.NET support and new languages in OpenIddict 3.0 beta4](https://kevinchalet.com/2020/10/02/introducing-quartz-net-support-and-new-languages-in-openiddict-3-0-beta4/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Introducing localization support in OpenIddict 3.0 beta3](https://kevinchalet.com/2020/08/03/introducing-localization-support-in-openiddict-3-0-beta3/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[OpenIddict 3.0 beta2 is out](https://kevinchalet.com/2020/07/08/openiddict-3-0-beta2-is-out/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Introducing OpenIddict 3.0 beta1](https://kevinchalet.com/2020/06/11/introducing-openiddict-3-0-beta1/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Adding OpenIddict 3.0 to an OWIN application](https://kevinchalet.com/2020/03/03/adding-openiddict-3-0-to-an-owin-application/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Creating an OpenID Connect server proxy with OpenIddict 3.0's degraded mode](https://kevinchalet.com/2020/02/18/creating-an-openid-connect-server-proxy-with-openiddict-3-0-s-degraded-mode/)** by [Kévin Chalet](https://github.com/kevinchalet)

*Posts written for previous versions of OpenIddict*: 

- **[Implementing an OpenIddict Authorization server: Social Login with GitHub](https://www.jerriepelser.com/blog/implementing-openiddict-authorization-server-part-2/)** by [Jerrie Pelser](https://github.com/jerriep)
- **[Implementing an OpenIddict Authorization server: A Basic Authorization Server](https://www.jerriepelser.com/blog/implementing-openiddict-authorization-server-part-1/)** by [Jerrie Pelser](https://github.com/jerriep)
- **[Implementing simple token authentication in ASP.NET Core with OpenIddict](https://kevinchalet.com/2017/01/30/implementing-simple-token-authentication-in-aspnet-core-with-openiddict/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Bearer Token Authentication in ASP.NET Core](https://devblogs.microsoft.com/aspnet/bearer-token-authentication-in-asp-net-core/)** by [Mike Rousos](https://github.com/mjrousos) (for the Microsoft .NET Web Development and Tools blog)
- **[Creating your own OpenID Connect server with ASOS](https://kevinchalet.com/2016/07/13/creating-your-own-openid-connect-server-with-asos-introduction/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Using OpenIddict to easily add token authentication to your .NET web apps](http://overengineer.net/Using-OpenIddict-to-easily-add-token-authentication-to-your-.NET-web-apps)** by [Josh Comley](https://github.com/joshcomley)

## Support

**Need help or wanna share your thoughts?** Don't hesitate to join us on Gitter or ask your question on StackOverflow:

- **Gitter: [https://gitter.im/openiddict/openiddict-core](https://gitter.im/openiddict/openiddict-core)**
- **StackOverflow: [https://stackoverflow.com/questions/tagged/openiddict](https://stackoverflow.com/questions/tagged/openiddict)**

## Nightly builds

If you want to try out the latest features and bug fixes, there is a MyGet feed with nightly builds
of OpenIddict.

To reference the OpenIddict MyGet feed, **create a `NuGet.config` file** (at the root of your solution):

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="nuget" value="https://api.nuget.org/v3/index.json" />
    <add key="openiddict" value="https://www.myget.org/F/openiddict/api/v3/index.json" />
  </packageSources>
</configuration>
```

## Contributors

**OpenIddict** is actively maintained by **[Kévin Chalet](https://github.com/kevinchalet)**. Contributions are welcome and can be submitted using pull requests.

**Special thanks to the following sponsors for their incredible support**:

- [David Hamilton](https://github.com/daveh101) from [DAM Good Media](https://www.damgoodmedia.com/)
- [Christopher McCrum](https://github.com/chrisjmccrum) from [Data Citadel](http://www.datacitadel.com/)

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
