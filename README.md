# OpenIddict

### The OpenID Connect stack you'll be addicted to.

[![Build status](https://github.com/openiddict/openiddict-core/workflows/build/badge.svg?branch=dev&event=push)](https://github.com/openiddict/openiddict-core/actions?query=workflow%3Abuild+branch%3Adev+event%3Apush)

## What's OpenIddict?

OpenIddict aims at providing a **versatile solution** to implement an **OpenID Connect server and token validation in any ASP.NET Core 2.1, 3.1 and 5.0 application**,
and starting in OpenIddict 3.0, **any ASP.NET 4.x application using Microsoft.Owin too**.

OpenIddict fully supports the **[code/implicit/hybrid flows](http://openid.net/specs/openid-connect-core-1_0.html)**, the **[client credentials/resource owner password grants](https://tools.ietf.org/html/rfc6749)** and the [device authorization flow](https://tools.ietf.org/html/rfc8628). You can also create your own custom grant types.

OpenIddict natively supports **[Entity Framework Core](https://www.nuget.org/packages/OpenIddict.EntityFrameworkCore)**, **[Entity Framework 6](https://www.nuget.org/packages/OpenIddict.EntityFramework)** and **[MongoDB](https://www.nuget.org/packages/OpenIddict.MongoDb)** out-of-the-box, but you can also provide your own stores.

## I want something simple and easy to configure

**Developers looking for a simple and turnkey solution are strongly encouraged to use [OrchardCore and its OpenID module](https://docs.orchardcore.net/en/dev/docs/reference/modules/OpenId/)**,
which is based on OpenIddict, comes with sensible defaults and offers a built-in management GUI to easily register OpenID client applications.

## Getting started

To implement a custom OpenID Connect server using OpenIddict, read **[Getting started](https://documentation.openiddict.com/guide/getting-started.html)**.

## Compatibility matrix

| Web framework version | .NET runtime version | OpenIddict 2.0 :exclamation:            | OpenIddict 2.0.1 :exclamation:          | OpenIddict 3.0                          |
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
| Microsoft.Owin 4.1    | .NET Framework 4.6.1 | :x:                                     | :x:                                     | :heavy_check_mark: :information_source: |
| Microsoft.Owin 4.1    | .NET Framework 4.7.2 | :x:                                     | :x:                                     | :heavy_check_mark:                      |
| Microsoft.Owin 4.1    | .NET Framework 4.8   | :x:                                     | :x:                                     | :heavy_check_mark:                      |

:exclamation: **Note: OpenIddict 2.x is no longer supported. Users are strongly encouraged to migrate to OpenIddict 3.0**.

:information_source: **Note: the following features are not available when targeting .NET Framework 4.6.1**:
 - X.509 development encryption/signing certificates: calling `AddDevelopmentEncryptionCertificate()` or `AddDevelopmentSigningCertificate()`
will result in a `PlatformNotSupportedException` being thrown at runtime if no valid development certificate can be found and a new one must be generated.
 - X.509 ECDSA signing certificates/keys: calling `AddSigningCertificate()` or `AddSigningKey()`
with an ECDSA certificate/key will always result in a `PlatformNotSupportedException` being thrown at runtime.

## Certification

Unlike many other identity providers, **OpenIddict is not a turnkey solution but a framework that requires writing custom code**
to be operational (typically, at least an authorization controller), making it a poor candidate for the certification program.

While a reference implementation could be submitted as-is, **this wouldn't guarantee that implementations deployed by OpenIddict users would be standard-compliant.**

Instead, **developers are encouraged to execute the conformance tests against their own deployment** once they've implemented their own logic.

> The samples repository contains [a dedicated sample](https://github.com/openiddict/openiddict-samples/tree/dev/samples/Contruum/Contruum.Server) specially designed to be used
> with the OpenID Connect Provider Certification tool and demonstrate that OpenIddict can be easily used in a certified implementation. To allow executing the certification tests
> as fast as possible, that sample doesn't include any membership or consent feature (two hardcoded identities are proposed for tests that require switching between identities).

--------------

## Resources

**Looking for additional resources to help you get started with 3.0?** Don't miss these interesting blog posts:

- **[OpenIddict 3.0 general availability](https://kevinchalet.com/2020/12/23/openiddict-3-0-general-availability/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Setting up an Authorization Server with OpenIddict](https://dev.to/robinvanderknaap/setting-up-an-authorization-server-with-openiddict-part-i-introduction-4jid)** by [Robin van der Knaap](https://dev.to/robinvanderknaap)
- **[Introducing OpenIddict 3.0's first release candidate version](https://kevinchalet.com/2020/11/17/introducing-openiddict-3-0-s-first-release-candidate-version/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[OpenIddict 3.0 beta6 is out](https://kevinchalet.com/2020/10/27/openiddict-3-0-beta6-is-out/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Introducing Quartz.NET support and new languages in OpenIddict 3.0 beta4](https://kevinchalet.com/2020/10/02/introducing-quartz-net-support-and-new-languages-in-openiddict-3-0-beta4/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Introducing localization support in OpenIddict 3.0 beta3](https://kevinchalet.com/2020/08/03/introducing-localization-support-in-openiddict-3-0-beta3/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[OpenIddict 3.0 beta2 is out](https://kevinchalet.com/2020/07/08/openiddict-3-0-beta2-is-out/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Introducing OpenIddict 3.0 beta1](https://kevinchalet.com/2020/06/11/introducing-openiddict-3-0-beta1/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Adding OpenIddict 3.0 to an OWIN application](https://kevinchalet.com/2020/03/03/adding-openiddict-3-0-to-an-owin-application/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Creating an OpenID Connect server proxy with OpenIddict 3.0's degraded mode](https://kevinchalet.com/2020/02/18/creating-an-openid-connect-server-proxy-with-openiddict-3-0-s-degraded-mode/)** by [Kévin Chalet](https://github.com/kevinchalet)

**OpenIddict-based projects maintained by third parties**:

- **[OrchardCore OpenID module](https://github.com/OrchardCMS/OrchardCore)**: turnkey OpenID Connect server and token validation solution, built with multitenancy in mind
- **[OpenIddict UI](https://github.com/thomasduft/openiddict-ui)** by [Thomas Duft](https://github.com/thomasduft): headless UI for managing client applications and scopes
- **[P41.OpenIddict.CouchDB](https://github.com/panoukos41/couchdb-openiddict)** by [Panos Athanasiou](https://github.com/panoukos41): CouchDB stores for OpenIddict

## Security policy

Security issues and bugs should be reported privately by emailing security@openiddict.com.
You should receive a response within 24 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

## Support

If you need support, please make sure you [sponsor the project](https://github.com/sponsors/kevinchalet) before creating a GitHub ticket.
If you're not a sponsor, you can post your questions on Gitter or StackOverflow:

- **Gitter: [https://gitter.im/openiddict/openiddict-core](https://gitter.im/openiddict/openiddict-core)**
- **StackOverflow: [https://stackoverflow.com/questions/tagged/openiddict](https://stackoverflow.com/questions/tagged/openiddict)**

## Nightly builds

If you want to try out the latest features and bug fixes, there is a MyGet feed with nightly builds of OpenIddict.
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

**Special thanks to our sponsors for their incredible support**:

- [Sébastien Ros](https://github.com/sebastienros)
- [mridentity](https://github.com/mridentity)
- [Andrew](https://github.com/GDreyV)
- [gustavdw](https://github.com/gustavdw)
- [Gillardo](https://github.com/Gillardo)
- [Dovydas Navickas](https://github.com/DovydasNavickas)
- [Christian Schmitt](https://github.com/schmitch)
- [Thomas W](https://github.com/ThreeScreenStudios)
- [torfikarl](https://github.com/torfikarl)
- [Lewis Cianci](https://github.com/lewcianci)
- [Florian Wachs](https://github.com/florianwachs)
- [Vasko Poposki](https://github.com/vaspop)
- [Sebastian Stehle](https://github.com/SebastianStehle)
- [Michael Hochriegl](https://github.com/MichaelHochriegl)
- [sunielreddy](https://github.com/sunielreddy)
- [Communicatie Cockpit](https://github.com/communicatie-cockpit)
- [Keith Turner](https://github.com/KeithT)
- [Virto Commerce](https://github.com/VirtoCommerce)

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
