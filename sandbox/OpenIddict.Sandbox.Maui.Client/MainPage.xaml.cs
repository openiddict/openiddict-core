using OpenIddict.Client.Maui;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.Sandbox.Maui.Client;

public partial class MainPage : ContentPage
{
    private readonly OpenIddictClientMauiAuthenticator _authenticator;

    public MainPage(OpenIddictClientMauiAuthenticator authenticator)
    {
        _authenticator = authenticator;

        InitializeComponent();
    }

    private async void OnLocalLoginButtonClicked(object sender, EventArgs e)
        => await AuthenticateAsync("https://localhost:44395/");

    private async void OnTwitterLoginButtonClicked(object sender, EventArgs e)
        => await AuthenticateAsync("https://twitter.com/");

    private async Task AuthenticateAsync(string provider)
    {
        try
        {
            var result = await _authenticator.AuthenticateAsync(new WebAuthenticatorOptions
            {
                Url = new Uri(provider, UriKind.Absolute)
            });

            await DisplayAlert("Authentication successful", $"Welcome, {result.Principal.FindFirst(Claims.Name)!.Value}.", "OK");
        }

        catch (TimeoutException)
        {
            await DisplayAlert("Authentication timed out", "The authentication process was aborted.", "OK");
        }

        catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
        {
            await DisplayAlert("Authorization denied", "The authorization was denied by the end user.", "OK");
        }

        catch (ProtocolException exception)
        {
            await DisplayAlert("Authentication failed", $"{exception.Error}: {exception.ErrorDescription}", "OK");
        }
    }
}
