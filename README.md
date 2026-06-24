# OpenIddict

### The OpenID Connect stack you'll be addicted to.

## What is OpenIddict?

OpenIddict aims at providing a **versatile solution** to implement **OpenID Connect client, server and token validation support in .NET applications**.

> [!TIP]
> While the client, server and token validation features can be used in any ASP.NET 4.6.2+ or
> [ASP.NET Core 2.3+ web application](https://documentation.openiddict.com/integrations/aspnet-core),
> the client feature can also be used in
> [Android, iOS, Linux, Mac Catalyst, macOS and Windows applications](https://documentation.openiddict.com/integrations/operating-systems)
> to integrate with OpenIddict-based identity providers or any other OAuth 2.0/OpenID Connect-compliant implementation.

OpenIddict fully supports the **[code/implicit/hybrid flows](http://openid.net/specs/openid-connect-core-1_0.html)**,
the **[client credentials/resource owner password grants](https://datatracker.ietf.org/doc/html/rfc6749)**,
the [device authorization flow](https://datatracker.ietf.org/doc/html/rfc8628) and the **[token exchange grant](https://datatracker.ietf.org/doc/html/rfc8693)**.

OpenIddict natively supports **[Entity Framework Core](https://www.nuget.org/packages/OpenIddict.EntityFrameworkCore)**,
**[Entity Framework 6](https://www.nuget.org/packages/OpenIddict.EntityFramework)** and **[MongoDB](https://www.nuget.org/packages/OpenIddict.MongoDb)**
out-of-the-box and custom stores can be implemented to support other providers.

--------------

## Getting started

**To implement a custom OpenID Connect server using OpenIddict, read [Getting started](https://documentation.openiddict.com/guides/getting-started/)**.

**Samples demonstrating how to use OpenIddict with the different OAuth 2.0/OpenID Connect flows**
can be found in the [dedicated repository](https://github.com/openiddict/openiddict-samples).

**Developers looking for a simple and turnkey solution are strongly encouraged to evaluate [Volo.OpenIddict.Pro](https://abp.io/modules/Volo.OpenIddict.Pro)**,
which is based on OpenIddict, supports all the common OAuth 2.0/OpenID Connect flows and offers a powerful applications/scopes management GUI.

> [!TIP]
> **Looking to integrate with a SAML2P Identity Provider (IDP) or Service Provider (SP)?** Rock Solid Knowledge,
> a sponsor of OpenIddict, is developing a range of identity components to enhance your OpenIddict solution.
> The first of these is their popular [SAML2P component](https://www.openiddictcomponents.com/?utm_source=openiddictgithubmain&utm_campaign=openiddict).

--------------

## Certification

Unlike many other identity providers, **OpenIddict is not a turnkey solution but a framework that requires writing custom code**
to be operational (typically, at least an authorization controller), making it a poor candidate for the certification program.

While a reference implementation could be submitted as-is, **this wouldn't guarantee that implementations deployed by OpenIddict users would be standard-compliant.**

Instead, **developers are encouraged to execute the conformance tests against their own deployment** once they've implemented their own logic.

> [!TIP]
> The samples repository contains [a dedicated sample](https://github.com/openiddict/openiddict-samples/tree/dev/samples/Contruum/Contruum.Server) specially designed to be used
> with the OpenID Connect Provider Certification tool and demonstrate that OpenIddict can be easily used in a certified implementation. To allow executing the certification tests
> as fast as possible, that sample doesn't include any membership or consent feature (two hardcoded identities are proposed for tests that require switching between identities).

--------------

## Resources

**Looking for additional resources to help you get started with OpenIddict?** Don't miss these interesting blog posts:

- **[OpenIddict 7.0 is out](https://kevinchalet.com/2025/07/07/openiddict-7-0-is-out/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[OpenIddict on AWS Serverless: adding interactive login](https://www.ganhammar.se/posts/openiddict-on-aws-serverless-with-interactive-login)** by [Anton Ganhammar](https://github.com/ganhammar)
- **[OpenIddict on AWS Serverless: flexible OAuth 2.0/OIDC provider](https://www.ganhammar.se/posts/openiddict-on-aws-serverless-flexible-oauth2-oidc-provider)** by [Anton Ganhammar](https://github.com/ganhammar)
- **[Transparent authentication gateway](https://alex-klaus.com/transparent-auth-gateway-1/)** by [Alex Klaus](https://github.com/aklaus)
- **[Introducing system integration support for the OpenIddict client](https://kevinchalet.com/2023/02/27/introducing-system-integration-support-for-the-openiddict-client/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Getting started with the OpenIddict web providers](https://kevinchalet.com/2022/12/16/getting-started-with-the-openiddict-web-providers/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Introducing the OpenIddict-powered providers](https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers/issues/694)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Introducing the OpenIddict client](https://kevinchalet.com/2022/02/25/introducing-the-openiddict-client/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Secure a Blazor WASM ASP.NET Core hosted app using BFF and OpenIddict](https://damienbod.com/2022/01/03/secure-a-blazor-wasm-asp-net-core-hosted-app-using-bff-and-openiddict/)** by [Damien Bowden](https://github.com/damienbod)
- **[Setting up an Authorization Server with OpenIddict](https://dev.to/robinvanderknaap/setting-up-an-authorization-server-with-openiddict-part-i-introduction-4jid)** by [Robin van der Knaap](https://dev.to/robinvanderknaap)
- **[Adding OpenIddict 3.0 to an OWIN application](https://kevinchalet.com/2020/03/03/adding-openiddict-3-0-to-an-owin-application/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Creating an OpenID Connect server proxy with OpenIddict 3.0's degraded mode](https://kevinchalet.com/2020/02/18/creating-an-openid-connect-server-proxy-with-openiddict-3-0-s-degraded-mode/)** by [Kévin Chalet](https://github.com/kevinchalet)

**OpenIddict-based projects maintained by third parties**:

- **[ABP Framework OpenIddict module](https://abp.io/)**: full-stack Web application framework for .NET
- **[OpenIddict.AmazonDynamoDB](https://github.com/ganhammar/OpenIddict.AmazonDynamoDB)** by [ganhammar](https://github.com/ganhammar): Amazon DynamoDB stores for OpenIddict
- **[OpenIddict UI](https://github.com/thomasduft/openiddict-ui)** by [Thomas Duft](https://github.com/thomasduft): headless UI for managing client applications and scopes
- **[OrchardCore OpenID module](https://github.com/OrchardCMS/OrchardCore)**: turnkey OpenID Connect server and token validation solution, built with multitenancy in mind
- **[P41.OpenIddict.CouchDB](https://github.com/panoukos41/couchdb-openiddict)** by [Panos Athanasiou](https://github.com/panoukos41): CouchDB stores for OpenIddict
- **[pixel-identity](https://github.com/Nfactor26/pixel-identity)** by [Nishant Singh](https://github.com/Nfactor26): Ready to host OpenID Connect service using OpenIddict and ASP.NET Identity with a Blazor-based UI for managing users, roles, applications and scopes with support for multiple databases.
- **[SharpGrip.OpenIddict.Api](https://github.com/SharpGrip/OpenIddict.Api)** by [SharpGrip](https://github.com/SharpGrip): SharpGrip OpenIddict API is an extension of the OpenIddict library exposing the OpenIddict entities through a RESTful API.

--------------

## Security policy

Security issues and bugs should be reported privately by emailing [security@openiddict.com](mailto:security@openiddict.com).
You should receive a response within 24 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

--------------

## Support policy

**If you need support, please first make sure you're [sponsoring the project](https://github.com/sponsors/kevinchalet) or are a regular contributor**:
GitHub tickets opened by users who haven't contributed to the project or don't actively sponsor it will be automatically closed.

> [!TIP]
> Depending on the tier you selected, you can open a GitHub ticket or send an email to [contact@openiddict.com](mailto:contact@openiddict.com) for private support.
>
> Alternatively, you can also post your question on [Gitter](https://app.gitter.im/#/room/#openiddict_openiddict-core:gitter.im).

**Support is only offered for the latest stable version of OpenIddict**. There are, however, two exceptions to this policy:
  - **ABP Framework users receive patches for OpenIddict for as long as ABP Framework itself is supported by Volosoft**
  (typically a year following the release of a major ABP version), whether they have a commercial ABP license or just use the free packages:

  | OpenIddict branch | ABP Framework branch | End of support date (estimated) |
  |-------------------|----------------------|---------------------------------|
  | 5.x               | 8.x                  | November 19, 2025               |
  | 6.x               | 9.x                  | Currently supported             |
  | 7.x (current)     | Not supported yet    | Not supported yet               |

  - **OpenIddict sponsors are offered extended support depending on the selected sponsorship tier:**
    - Tier 6 sponsors get full support for the previous version 1 month following the release of a new major version.
    - Tier 7 sponsors get full support for the previous version 6 months following the release of a new major version.
    - Tier 8 sponsors get full support for the previous version 12 months following the release of a new major version.
    - Tier 9 sponsors get full support for the previous version 24 months following the release of a new major version.

  | OpenIddict branch | Sponsorship tier | End of support date |
  |-------------------|------------------|---------------------|
  | 5.x               | Tier 6           | January 17, 2025    |
  | 5.x               | Tier 7           | June 17, 2025       |
  | 5.x               | Tier 8           | December 17, 2025   |
  | 5.x               | Tier 9           | December 17, 2026   |
  |                   |                  |                     |
  | 6.x               | Tier 6           | August 7, 2025      |
  | 6.x               | Tier 7           | January 7, 2026     |
  | 6.x               | Tier 8           | July 7, 2026        |
  | 6.x               | Tier 9           | July 7, 2027        |
  |                   |                  |                     |
  | 7.x (current)     | Any              | Currently supported |

> [!TIP]
> For more information on the different tiers and the benefits they offer, visit [GitHub Sponsors](https://github.com/sponsors/kevinchalet).

--------------

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

**Special thanks to [our sponsors](https://github.com/sponsors/kevinchalet#sponsors) for their incredible support**:

<a href="https://volosoft.com/">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://volosoft.com/assets/logos/volosoft-logo-light.svg">
    <img src="https://volosoft.com/assets/logos/volosoft-logo-dark.svg" width="500px" alt="Volosoft logo" />
  </picture>
</a>

<br />
<br />

<a href="https://www.openiddictcomponents.com/">
  <img src="https://www.openiddictcomponents.com/img/openiddict-components-logo.png" width="400px" alt="OpenIddict Components logo" />
</a>

<br />
<br />

<!-- sponsors --><a href="https://github.com/sebastienros"><img src="https:&#x2F;&#x2F;github.com&#x2F;sebastienros.png" width="60px" alt="User avatar: Sébastien Ros" /></a><a href="https://github.com/SebastianStehle"><img src="https:&#x2F;&#x2F;github.com&#x2F;SebastianStehle.png" width="60px" alt="User avatar: Sebastian Stehle" /></a><a href="https://github.com/communicatie-cockpit"><img src="https:&#x2F;&#x2F;github.com&#x2F;communicatie-cockpit.png" width="60px" alt="User avatar: Communicatie Cockpit" /></a><a href="https://github.com/KeithT"><img src="https:&#x2F;&#x2F;github.com&#x2F;KeithT.png" width="60px" alt="User avatar: " /></a><a href="https://github.com/Skrypt"><img src="https:&#x2F;&#x2F;github.com&#x2F;Skrypt.png" width="60px" alt="User avatar: Jasmin Savard" /></a><a href="https://github.com/ThomasBjallas"><img src="https:&#x2F;&#x2F;github.com&#x2F;ThomasBjallas.png" width="60px" alt="User avatar: Thomas" /></a><a href="https://github.com/jonmartinsson"><img src="https:&#x2F;&#x2F;github.com&#x2F;jonmartinsson.png" width="60px" alt="User avatar: " /></a><a href="https://github.com/EYERIDE-Fleet-Management-System"><img src="https:&#x2F;&#x2F;github.com&#x2F;EYERIDE-Fleet-Management-System.png" width="60px" alt="User avatar: EYERIDE Fleet Management System" /></a><a href="https://github.com/ravindUwU"><img src="https:&#x2F;&#x2F;github.com&#x2F;ravindUwU.png" width="60px" alt="User avatar: Ravindu Liyanapathirana" /></a><a href="https://github.com/ahanoff"><img src="https:&#x2F;&#x2F;github.com&#x2F;ahanoff.png" width="60px" alt="User avatar: Akhan Zhakiyanov" /></a><a href="https://github.com/blowdart"><img src="https:&#x2F;&#x2F;github.com&#x2F;blowdart.png" width="60px" alt="User avatar: Barry Dorrans" /></a><a href="https://github.com/devqsrl"><img src="https:&#x2F;&#x2F;github.com&#x2F;devqsrl.png" width="60px" alt="User avatar: DevQ S.r.l." /></a><a href="https://github.com/dgxhubbard"><img src="https:&#x2F;&#x2F;github.com&#x2F;dgxhubbard.png" width="60px" alt="User avatar: " /></a><a href="https://github.com/forterro"><img src="https:&#x2F;&#x2F;github.com&#x2F;forterro.png" width="60px" alt="User avatar: Forterro" /></a><a href="https://github.com/MarcelMalik"><img src="https:&#x2F;&#x2F;github.com&#x2F;MarcelMalik.png" width="60px" alt="User avatar: Marcel" /></a><a href="https://github.com/jwillmer"><img src="https:&#x2F;&#x2F;github.com&#x2F;jwillmer.png" width="60px" alt="User avatar: Jens Willmer" /></a><a href="https://github.com/BlauhausTechnology"><img src="https:&#x2F;&#x2F;github.com&#x2F;BlauhausTechnology.png" width="60px" alt="User avatar: Blauhaus Technology (Pty) Ltd" /></a><a href="https://github.com/trejjam"><img src="https:&#x2F;&#x2F;github.com&#x2F;trejjam.png" width="60px" alt="User avatar: Jan Trejbal" /></a><a href="https://github.com/aviationexam"><img src="https:&#x2F;&#x2F;github.com&#x2F;aviationexam.png" width="60px" alt="User avatar: Aviationexam s.r.o." /></a><a href="https://github.com/jeroenbai"><img src="https:&#x2F;&#x2F;github.com&#x2F;jeroenbai.png" width="60px" alt="User avatar: Jeroen Baidenmann" /></a><a href="https://github.com/Lombiq"><img src="https:&#x2F;&#x2F;github.com&#x2F;Lombiq.png" width="60px" alt="User avatar: Lombiq Technologies Ltd." /></a><a href="https://github.com/andrewbabbittdev"><img src="https:&#x2F;&#x2F;github.com&#x2F;andrewbabbittdev.png" width="60px" alt="User avatar: Andrew Babbitt" /></a><a href="https://github.com/stevenkuhn"><img src="https:&#x2F;&#x2F;github.com&#x2F;stevenkuhn.png" width="60px" alt="User avatar: Steven Kuhn" /></a><a href="https://github.com/softawaregmbh"><img src="https:&#x2F;&#x2F;github.com&#x2F;softawaregmbh.png" width="60px" alt="User avatar: softaware gmbh" /></a><a href="https://github.com/SingularSystems"><img src="https:&#x2F;&#x2F;github.com&#x2F;SingularSystems.png" width="60px" alt="User avatar: Singular Systems" /></a><a href="https://github.com/SCP-srl"><img src="https:&#x2F;&#x2F;github.com&#x2F;SCP-srl.png" width="60px" alt="User avatar: SCP-srl" /></a><a href="https://github.com/realisable"><img src="https:&#x2F;&#x2F;github.com&#x2F;realisable.png" width="60px" alt="User avatar: Realisable Software" /></a><a href="https://github.com/sfmskywalker"><img src="https:&#x2F;&#x2F;github.com&#x2F;sfmskywalker.png" width="60px" alt="User avatar: Sipke Schoorstra" /></a><a href="https://github.com/JamesHough"><img src="https:&#x2F;&#x2F;github.com&#x2F;JamesHough.png" width="60px" alt="User avatar: James Hough" /></a><a href="https://github.com/kaputsyn"><img src="https:&#x2F;&#x2F;github.com&#x2F;kaputsyn.png" width="60px" alt="User avatar: " /></a><a href="https://github.com/jberzy"><img src="https:&#x2F;&#x2F;github.com&#x2F;jberzy.png" width="60px" alt="User avatar: " /></a><a href="https://github.com/arwin-swapna"><img src="https:&#x2F;&#x2F;github.com&#x2F;arwin-swapna.png" width="60px" alt="User avatar: Arwin" /></a><a href="https://github.com/zunda-inc"><img src="https:&#x2F;&#x2F;github.com&#x2F;zunda-inc.png" width="60px" alt="User avatar: ZUNDA Inc." /></a><a href="https://github.com/antonypetras"><img src="https:&#x2F;&#x2F;github.com&#x2F;antonypetras.png" width="60px" alt="User avatar: Antony Petras" /></a><!-- sponsors -->

--------------

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely.
See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
