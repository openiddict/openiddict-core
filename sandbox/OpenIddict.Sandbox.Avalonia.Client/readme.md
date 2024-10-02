# Avalonia sample app guide

This guide goes through how an Avalonia UI app can use OpenIddict to authenticate to an OpenIddict-powered server.

For this, you can user either 
- OpenIddict.Sandbox.AspNetCore.Server
- or OpenIddict.Sandbox.AspNet.Server

## Run the sample

1. First, you need to set up a dev tunnel.
   Thereafter, run the server and take note of the URL.
2. In Startup.cs find the line: `// Swap Issuer URL` and set your issuer url.
    To understand why this is necessary, see **ERR004** and **ERR005**
3. Find and uncomment the line: `// options.AddCertificatesForMobileApps();` 
   And comment out 
    ```csharp
        ptions.AddDevelopmentEncryptionCertificate()
              .AddDevelopmentSigningCertificate();
    ```
    To understand why this is necessary, see **ERR003**

4. In `MauiProgram` (for Maui) or `AvaloniaSetup` (for Avalonia), find the `OpenIddictClientRegistration` and update the `Issuer` url to match yours
    ```
        // Add a client registration matching the client application definition in the server project.
        options.AddRegistration(new OpenIddictClientRegistration
        {
            Issuer = new Uri("https://localhost:44349/", UriKind.Absolute),
            ProviderName = "Local",
    ```

4. You can now run any sample app (Maui iOS,Windows or Avalonia Android/iOS/Desktop)


## How this was implemented:

### Configure Microsoft.Extensions.DependencyInjection
First, we added an Avalonia XPat project.
We then added dependency injection using `Microsoft.Extensions.DependencyInjection`
Note, that we override the creation of the Avalonia `App` e.g. in `OpenIddict.Sandbox.Avalonia.Client.Android.MainActivity`:
```csharp
  protected override AppBuilder CreateAppBuilder()
    {
        return AppBuilder.Configure<App>(() =>
        {
            var services = new ServiceCollection();
            var app = new App();
            app.ConfigureServices(services);
            var provider = services.BuildServiceProvider();
            app.Provider = provider;
            this.Provider = provider;

            return app;
        }).UseAndroid();
    }

    public IServiceProvider Provider { get; set; }
```
This is, so we can 
- configure services in our `OpenIddict.Sandbox.Avalonia.Client.Application`
- and pass the `IServiceProvider` to it and the `MainActivity`

This way, when the `OpenIddict.Sandbox.Avalonia.Client.Application.OnFrameworkInitializationCompleted()` callback is invoked, we do have a `IServiceProvider` and can use it to resolve the `MainViewModel`
And we can emulate the `Maui` behavior for the interfaces `IMauiInitializeService` and `IMauiInitializeScopedService`
```
    /// <summary>
    /// Represents a service that is initialized during the application construction.
    /// </summary>
    /// <remarks>
    /// This service is initialized during the MauiAppBuilder.Build() method. It is
    /// executed once per application using the root service provider.
    /// </remarks>
    public interface IMauiInitializeService
    {
        void Initialize(IServiceProvider services);
    }   
    /// <summary>
    /// Represents a service that is initialized during the window construction.
    /// </summary>
    /// <remarks>
    /// This service is initialized during the creation of a window. It is
    /// executed once per window using the window-scoped service provider.
    /// </remarks>
    public interface IMauiInitializeScopedService
    {
        void Initialize(IServiceProvider services);
    }
```
 
Also, in the `MainActivity`, we can use the `IServiceProvider` for a callback we will explain later.

### Copying the MAUI `MainPage` logic
The code in the `MainViewModel`  is more or less copied from the Maui sample.

### Registering callbacks for the custom URI scheme
Then, for the callback, we needed to register a custom uri scheme `com.openiddict.sandbox.avalonia.client` that is also registered in the server projects for the client `avalonia`

#### Desktop (Windows)
For the `OpenIddict.Sandbox.Avalonia.Client.Desktop` this was simple, as we copied the code from the `OpenIddict.Sandbox.Wpf.Client.Worker` and put it into an extension method `AppBuilderExtensions.RegisterAppUrl`
This then is invoked at application initialization:
```csharp
sealed class Program
{
    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static void Main(string[] args) =>
        BuildAvaloniaApp()
        // custom: registering app url for deep links
        .RegisterAppUrl()
        .StartWithClassicDesktopLifetime(args);

```

#### Android
For Android, it was a bit more work:
We had to configure the `IntentFilter` on the `MainActivity`:
```diff
[Activity(
    Label = "OpenIddict.Sandbox.Avalonia.Client.Android",
    Theme = "@style/MyTheme.NoActionBar",
    Icon = "@drawable/icon",
    MainLauncher = true,
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode)]
+// Intent filter for custom URI scheme
+[IntentFilter(new[] { Intent.ActionView },
+    Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable },
+    DataScheme = "com.openiddict.sandbox.avalonia.client")]
public class MainActivity : AvaloniaMainActivity<App>
{
```

and wrote an override of `OnCreate` that forwarded the intent to the `OpenIddictClientSystemIntegraionService`:
```
    // Handle the custom URL scheme
    if (intent?.Data is not null)
    {
        var scheme = intent?.Data?.Scheme;
        await Provider.GetRequiredService<OpenIddictClientSystemIntegrationService>().HandleCustomTabsIntentAsync(intent!);
    }
```

With that in place, the app opened upon successful authentication, but only show the splash screen.
This is because by default, an `Activity` is instanciated when receiving a new `Intent`. This, however clears our current UI state (View and ViewModel).
To fix this, we had to configure the `Activity` such that it is reused
```diff
[Activity(
    Label = "OpenIddict.Sandbox.Avalonia.Client.Android",
    Theme = "@style/MyTheme.NoActionBar",
    Icon = "@drawable/icon",
    MainLauncher = true,
+    // LauchMode singleTask so that the activity is not recreated
+    LaunchMode=LaunchMode.SingleTask,
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode)]
// Intent filter for custom URI scheme
[IntentFilter(new[] { Intent.ActionView },
    Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable },
    DataScheme = "com.openiddict.sandbox.avalonia.client")]
public class MainActivity : AvaloniaMainActivity<App>
{
```

Which in turn causes `OnCreate` to not be called anymore when a new `Intent` is received.
Rather, we had to override `OnNewIntent`
```csharp

    protected override async void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);

        // Handle the custom URL scheme
        if (intent?.Data is not null)
        {
            var scheme = intent?.Data?.Scheme;
            await Provider.GetRequiredService<OpenIddictClientSystemIntegrationService>().HandleCustomTabsIntentAsync(intent!);
        }
    }
```

#### iOS

For iOS, we simply added the following configuration to the end of the **Info.plist** file:

```diff

+	<key>CFBundleURLTypes</key>
+	<array>
+		<dict>
+			<key>CFBundleURLName</key>
+			<string>Type d&apos;URL 1</string>
+			<key>CFBundleURLSchemes</key>
+			<array>
+				<string>com.openiddict.sandbox.avalonia.client</string>
+			</array>
+			<key>CFBundleTypeRole</key>
+			<string>Editor</string>
+		</dict>
+	</array>

</dict>
</plist>

```

## The issues we faced when implementing the sample

### ERR001 Android build error
When building the Android project, the following build error can occur:
> Failed to generate Java type for class: Android.Support.V4.View.Accessibility.AccessibilityManagerCompat/IAccessibilityStateChangeListenerImplementor due to MAX_PATH: System.IO.DirectoryNotFoundException: Could not find a part of the path 'C:\Users\Administrator\OneDrive\Hobbies\Software\Developments\ProjectNameAboutThisLength\ProjectNameAboutThisLength.Clients.XamarinClient.Android\obj\Debug\90\android\src\mono\android\support\v4\view\accessibility\AccessibilityManagerCompat_AccessibilityStateChangeListenerImplementor.java'.
>  at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)
>  at System.IO.File.InternalDelete(String path, Boolean checkHost)
>  at System.IO.File.Delete(String path)
>  at Xamarin.Android.Tools.Files.CopyIfStreamChanged(Stream stream, String destination)
>  at Xamarin.Android.Tasks.GenerateJavaStubs.CreateJavaSources(IEnumerable`1 javaTypes, TypeDefinitionCache cache)	ProjectNameAboutThisLength.Clients.XamarinClient.Android

This happens when you run into a windows limitation.
From windows 10 and up, you can overcome this by [setting the regestry key 'LongPathsEnabled' to 1](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry#enable-long-paths-in-windows-10-version-1607-and-later)
The full path of the key: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled`

You can do this in powershell:
```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```


### ERR002 iOS Runtime error (EF Core)
When creating the database in `Worker.Initialize()` the call to `context.Database.EnsureCreated()` returns the error `Model building is not supported when publishing with NativeAOT. Use a compiled model`

This was fixed following the [solution described here](https://github.com/dotnet/maui/issues/23653)
by adding the following propertygroup to the iOS.csproj:

```xml
	<PropertyGroup>
		<MtouchInterpreter>all</MtouchInterpreter>
		<UseInterpreter>True</UseInterpreter>
	</PropertyGroup>
```

### ERR003 iOS/Android Runtime error (Microsoft.Extensions.Options.IOptionsMonitor)
When trying to run the app, clicking/tapping "login" yields the error

iOS:
> Interop+AppleCrypto+AppleCommonCryptoCryptographicException: 'A required entitlement isn't present.'

Android:
> System.PlatformNotSupportedException: 'The PKCS#12 PersistKeySet flag is not supported on this platform.'

at `OpenIddictClientFactory.CreateTransactionAsync()`

This seems to have to do with the `Microsoft.Extensions.Options.IOptionsMonitor` implementation since the error is thrown by `_options.CurrentValue`

This issue seems to stem from the fact, that neither Android emulators nor iOS simulators can actually create an X509 certificate locally storing it in the machine store.
Error is thrown in `OpenIddictClientBuilder` at the line 254 (on android seemingly because of the flag `PersistKeySet`)
```csharp
                    certificates.Insert(0, certificate = new X509Certificate2(data, string.Empty, flags));
```

**Solution** do not use 
```csharp
options.AddDevelopmentEncryptionCertificate()
       .AddDevelopmentSigningCertificate();
```
since that creats a X509 certificate and tries to save it in the local machine store. This does not work on iOS and Android and even _if_, the connection to the server would not work, since both would have their own machine store and, thus, use totally different certificates (rendering them incompatible)


For the same reason using the Ephemeral... keys will not work:

```csharp
options.AddEphemeralEncryptionKey()
       .AddEphemeralSigningKey();
```
results in the error

> OpenIddict.Abstractions.OpenIddictExceptions+ProtocolException: 'An error occurred while sending the cryptography request.
>  Error: server_error
>  Error description: An error occurred while communicating with the remote HTTP server.
>  Error URI: https://documentation.openiddict.com/errors/ID2136'

Again: Server and client use different (thus incompatible) certificates!

**Solution** generate your own keys and certificate:

You can create your own symmetric and asymmetric keys.
For the asymmetric one, you can [use the following code](https://dotnetfiddle.net/k0uFLZ):
```csharp
using System.Security.Cryptography;
using System;
					
public class Program
{
	public static void Main()
	{
		var rsa = RSA.Create(2048);
		string privateKeyXml = rsa.ToXmlString(true);
		Console.WriteLine(privateKeyXml);
	}
}
```

Register those in **client and server**:
```diff
// Register the OpenIddict client components.
.AddClient(options =>
{
    // Note: this sample uses the authorization code and refresh token
    // flows, but you can enable the other flows if necessary.
    options.AllowAuthorizationCodeFlow()
           .AllowRefreshTokenFlow();

    // Register the signing and encryption credentials used to protect
    // sensitive data like the state tokens produced by OpenIddict.
-    options.AddDevelopmentEncryptionCertificate()
-           .AddDevelopmentSigningCertificate();
    
+    var privateKeyXml = "<RSAKeyValue><Modulus>uSQBwbidg8/lAw3N3xeWmc9uYQPMHH5fODGmER6uXRzzJaL8upFWXanwts7ILNFOFAWogxQuWaTqu4dUFDVuXhJsdxpT4YZy0+k8QEMyBi6VIenQtKhYgiCgx9RK6cAuXRN1X6iQ2F+3MaenUGxztEOSQ1iJarV7E5od0o0doDl0TcW/wVqnwpAc5j8K/06kICuy1Pb1glHZsF8vzCgTPwdBTAYLGbzJWWxpLNiEFDuvJR6lopSSxKpurvzYXgpZHMZuOUlmQM/XGXjCYctHldAmr+gp8/xtufx3w2/V3gApLS6kWdkA9xazLOt7Xqb2QBGNGbunVzhtGg2rBYdBXQ==</Modulus><Exponent>AQAB</Exponent><P>wiiY1qCfHaiO+FoVpB3OocUYtqI9WvXUV2tk/JIOVuBth5oRg01GMN1cMA085YcwlV1d2RQVqGXdhAKHUwyi73luFQ/yt5ehemPUQPau03Pv8GkySLSGsbwuK+FKpDQ9kdupG1eW6dBt91um4Q1Gtu+GAJ2LkucYRHA2yx6osIs=</P><Q>9BwZ5gtnMw70n/h8NvULco5RxxpfoQ++2D7iQ6rc7i27/k53E0is2L03PP/LR8bV/14z+ixMW6rH7G2d475NIzFTrR4HjZdf+i05Fq7N/xvNCLrUvAd0CWqxYrume0t9zfw62JQtp5IYQ3g9K7DxUwfY9qVwYlZByLkgrUz26rc=</Q><DP>m2n5pVte4lOpVXxudDbzzqPA+3f0WtoKBYvOgym6VqpAolmeCRcSx0x5XXFLPIMxTW42D+w2xdv8K44GmmC0D7KIfk2MwI6cUCaWoQWUvWfBORRLjs0KQDzcTH2CzNuQKS/GNj+vaitPyr9PXjfNUeN6xQVW0tkuoKGeCorZBq8=</DP><DQ>HOd26ZZQEeuja42wp5E8WcQgSsMEr719i31mrTx+DHW93M7NqqrgTImbEM348/bHQAWXgffc0r3WDlisaVsPJyugDM+RdWKHKshQCi+IlLxl+rKknd8EDlljx50QiWjW7J0BGsPw4/aYiOSj2ZiJ+prjRdExDXPJNks1Y0/JrOE=</DQ><InverseQ>g+JNJBZbKFIY5jWZxCeX7TW25KpR498x+0yGJlzCwy23JbBGDupt2tsBnhXr8KuTxSfMOGWtazQeipI//XyLCvV7BohkL6PhzMKKHwAoM/0xNaqA0d5t9Q32OqEn6I+deu4SF4OwMXkQ96xGp0zLlsWnw3HdG2rVtx5KYARMmGA=</InverseQ><D>YA+CqdT0RXQUyyTacKp4hY3PI58oxI/9L9by52cX6VAgCKMsplDKkwad0vwveLGQ5WqaKIjME88xy+NHiMTAYycECDgs1ZNA+RrHHEDBL9vznQkINPQ0GDB9u7E2vVnttHVoLR31KY9gKe9nLJ9Y2WtF9JN3mVpYZa9NUfXOLVc+zs6ChwqfryfrkgQGHZXNFtwYhG4KuOLkrQy2S4etJEWn+NMbJVYEmy1Sg99BZs4eyi0666B30ofUsx6GwyCa9IXgDm4cJnUDQu0ZEGNU7LX+p9lFym13DkWt4z9TuE3QeOSr7jHEQz1CdE8a4zsqdf3TKP2Fl05+URL35kr/MQ==</D></RSAKeyValue>";
+    var rsa = RSA.Create(2048);
+    rsa.FromXmlString(privateKeyXml);
+
+    options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));
+    options.AddSigningKey(new RsaSecurityKey(rsa));

```

### ERR004 Android/iOS/Windows: OpenIddict.Abstractions.OpenIddictExceptions+ProtocolException: 'An error occurred while extracting the configuration response.

If you receive the following error:
> OpenIddict.Abstractions.OpenIddictExceptions+ProtocolException: 'An error occurred while extracting the configuration response.
>  Error: server_error
>  Error description: An unsupported response was returned by the remote authorization server.
>  Error URI: https://documentation.openiddict.com/errors/ID2162'
the issue is that the client cannot connect to the server. 
This happens when running the server on your local machine and trying to access it from your mobile device or Android emulator/iOS Simulator.

**Solution** you need to use the Visual Studio Dev Tunnel to connect to your server. If you provide the wrong URL, this is the error you will get!


**TIP** If you need to inspect the requests sent back and forth via the Visual Studio Dev Tunnel, simple append `-inspect` to the host name.
For example, if the tunnel URL is https://ID-8080.usw2.devtunnels.ms, network activity can be inspected at https://ID-8080-inspect.usw2.devtunnels.ms.


### ERR005 Android/iOS: 'Connection failure'
Another error: 
> System.Net.Http.HttpRequestException: 'Connection failure'
We somehow did not configure the server url correctly.
The call to get the JWKS should also use the dev tunnel, but the request in `OpenIddictClientSystemNetHttpHandler.HandleAsync` sends it to
`"https://localhost:44349/.well-known/jwks"`
How can that be?


Retrieving the `/.well-known/openid-configuration` reveals the source of the problem:

```json
{
  "issuer": "https://vsr1d2md-44349.euw.devtunnels.ms/",
  "authorization_endpoint": "https://localhost:44349/connect/authorize",
  "token_endpoint": "https://localhost:44349/connect/token",
  "introspection_endpoint": "https://localhost:44349/connect/introspect",
  "end_session_endpoint": "https://localhost:44349/connect/logout",
  "userinfo_endpoint": "https://localhost:44349/connect/userinfo",
  "device_authorization_endpoint": "https://localhost:44349/connect/device",
  "jwks_uri": "https://localhost:44349/.well-known/jwks",
  "grant_types_supported": [
    "authorization_code",
    "urn:ietf:params:oauth:grant-type:device_code",
    "password",
    "refresh_token"
  ],
  ...
 }
```
while the issuer is set to the dev tunnel fqdn, all other endpoints still point to localhost!
To remedy this, you need to change all your `...EndpointUris` from a relative uri to a fully qualified one - using the issuer uri as base.

The following points are **IMPORTANT**:
- the fully qualified URL must be the FIRST to be registered. This is because when OpenIdict creates the `/.well-known/openid-configuration` (in the `Openiddict.Server.AttachEndPoints` handler) this hanldler gets the **first** `...EndpointUri` of any kind and either takes it as it is in case it's an abslute uri, or appends the relative uri to the current Request.Uri.
- Also, we **must** still include the relative URIs as second parameter otherwise, for example the `/.well-known/jwks` endpoint returns a 404. Or the login process fails with a 
> System.InvalidOperationException: 'The OpenID Connect request cannot be retrieved.'
on the server side.

```diff

	// Register the OpenIddict server components.
	.AddServer(options =>
	{
+		var uri = new Uri("https://vsr1d2md-44349.euw.devtunnels.ms/");

+		options.SetIssuer(uri);

+		string Fqdn(Uri uri, string relative) => new Uri(uri, relative).ToString(); ;

+		// Enable the authorization, device, introspection,
+		// logout, token, userinfo and verification endpoints.
+		options = options.SetAuthorizationEndpointUris(Fqdn(uri, "connect/authorize"), "connect/authorize")
+			   .SetDeviceEndpointUris(Fqdn(uri, "connect/device"),"connect/device")
+			   .SetIntrospectionEndpointUris(Fqdn(uri, "connect/introspect"),"connect/introspect")
+			   .SetLogoutEndpointUris(Fqdn(uri, "connect/logout"), "connect/logout")
+			   .SetTokenEndpointUris(Fqdn(uri, "connect/token"), "connect/token")
+			   .SetUserinfoEndpointUris(Fqdn(uri, "connect/userinfo"), "connect/userinfo")
+			   .SetVerificationEndpointUris(Fqdn(uri, "connect/verify"),"connect/verify")
+ 				// IMPORTANT: Set the cryptographicendpointuri which is normally not done in any openiddict sample!
+				// AND keep the relative urls!
+			   .SetCryptographyEndpointUris(Fqdn(uri, ".well-known/jwks"), ".well-known/jwks");
-		options.SetAuthorizationEndpointUris("connect/authorize")
-		       .SetDeviceEndpointUris("connect/device")
-                .SetIntrospectionEndpointUris("connect/introspect")
-                .SetLogoutEndpointUris("connect/logout")
-                .SetTokenEndpointUris("connect/token")
-                .SetUserinfoEndpointUris("connect/userinfo")
-                .SetVerificationEndpointUris("connect/verify");

	// ...
	}

```


### ERR006 Android
Finally, the Android app is re-opened, but only shows the splash screen. Why is that?

You probably included the following intent filter so that the app is opened using the custom URI scheme `com.openiddict.sandbox.avalonia.client`

```diff

[Activity(
    Label = "OpenIddict.Sandbox.Avalonia.Client.Android",
    Theme = "@style/MyTheme.NoActionBar",
    Icon = "@drawable/icon",
    MainLauncher = true,
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode)]
+[IntentFilter(new[] { Intent.ActionView },
+    Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable },
+    DataScheme = "com.openiddict.sandbox.avalonia.client")]
public class MainActivity : AvaloniaMainActivity<App>
{

``` 

However, this does not preserve the current Activity. Rather, a new instance is created and our app completely looses its memory/context.
We need to explicitly configure the Activity so that it is not re-created (re-instanciated) when an intent comes in:

```diff
[Activity(
    Label = "OpenIddict.Sandbox.Avalonia.Client.Android",
    Theme = "@style/MyTheme.NoActionBar",
    Icon = "@drawable/icon",
    MainLauncher = true,
+    // LauchMode singleTask so that the activity is not recreated
+    LaunchMode=LaunchMode.SingleTask,
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode)]
// Intent filter for custom URI scheme
[IntentFilter(new[] { Intent.ActionView },
    Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable },
    DataScheme = "com.openiddict.sandbox.avalonia.client")]
public class MainActivity : AvaloniaMainActivity<App>
{

```

Finally, when the authentication flow returns to our app using the custom URI scheme "com.openiddict.sandbox.avalonia.client", we need to forward that Intent to OpenIddict, so that it can complete the authentication flow.
For this, add the following `OnNewIntent` override to MainActivity

```csharp 
public class MainActivity : AvaloniaMainActivity<App>
{
    // ...

    protected override async void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);

        // Handle the custom URL scheme
        if (intent?.Data is not null)
        {
            var scheme = intent?.Data?.Scheme;
            await Provider.GetRequiredService<OpenIddictClientSystemIntegrationService>().HandleCustomTabsIntentAsync(intent!);
        }
    }
}
```

This will take the intent, resolve the `OpenIddictClientSystemIntegrationService` call its `HandleCustomTabsIntentAsync` method which is responsible for handling the intent (e.g. exracting all auth information like access_token etc._)