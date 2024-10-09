# Run the sample on Android and iOS

In order to try out the Avalonia sample app with a local _OpenIddict.Sandbox.AspNetCore.Server_, do the following

1. Since Android and iOS run on separate devices an emulator/simulator, you need to set up a dev-tunnel for _OpenIddict.Sandbox.AspNetCore.Server_. 
2. Open the _Dev Tunnels_ view, open the settings of your new dev tunnel and ensure the _Use Tunnel Domain_ is checked for the HTTPS port so the dev-tunnel domain is forwarded to OpenIddict.
   Note: In case you are running IIS Express, update your applicationhost.config and ensure that IIS also listens to the dev tunnel domain:
```diff

    <bindings>
        <binding protocol="http" bindingInformation="*:55946:localhost" />
+        <binding protocol="https" bindingInformation="*:44349:*" />
        <binding protocol="https" bindingInformation="*:44349:localhost" />
    </bindings>
```

3. Thereafter, run the server and take note of the URL - we will configure it as `IssuerUrl`
4. In the Startup.cs of _OpenIddict.Sandbox.AspNetCore.Server_ find the line: `// Set Issuer URL` and set your issuer url.
5. iOS and Android: In your client project, find and uncomment the line: `// options.AddCertificatesForMobileApps();` which creates new Encryption- and Singing-keys in code. 
   Comment out as it does not work on iOS or Android
```csharp
        options.AddDevelopmentEncryptionCertificate()
              .AddDevelopmentSigningCertificate();
```
6. In your client project, set the `IssuerUri` of your `OpenIddictClientRegistration` to the domain name of your dev tunnel
7. In `MauiProgram` (for Maui) or `AvaloniaSetup` (for Avalonia), find the `OpenIddictClientRegistration` and update the `Issuer` url to match yours
```diff
                // Add a client registration matching the client application definition in the server project.
                options.AddRegistration(new OpenIddictClientRegistration
                {
-                    Issuer = new Uri("https://localhost:44395/", UriKind.Absolute),
+                    Issuer = new Uri("https://vsr1d2md-44349.euw.devtunnels.ms/", UriKind.Absolute),
                    ProviderName = "Local",
                    ClientId = "avalonia",
                    ...
````

4. You can now run any sample app (Maui iOS,Windows or Avalonia Android/iOS/Desktop)