using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Sandbox.Maui.Client;

public partial class MainPage : ContentPage
{
    private readonly OpenIddictClientService _service;

    public MainPage(OpenIddictClientService service)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));

        InitializeComponent();
    }

    private async void OnLocalLoginButtonClicked(object sender, EventArgs e)
        => await AuthenticateAsync("Local");

    private async void OnTwitterLoginButtonClicked(object sender, EventArgs e)
        => await AuthenticateAsync(Providers.Twitter);

    private async Task AuthenticateAsync(string provider)
    {
        using var source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(90));

        try
        {
            // Ask OpenIddict to initiate the challenge and launch the system browser
            // to allow the user to complete the interactive authentication dance.
            var nonce = await _service.ChallengeWithBrowserAsync(
                provider, cancellationToken: source.Token);

            // Wait until the user approved or rejected the authorization
            // demand and retrieve the resulting claims-based principal.
            var (_, _, principal) = await _service.AuthenticateWithBrowserAsync(
                nonce, cancellationToken: source.Token);

            await DisplayAlert("Authentication successful", $"Welcome, {principal.FindFirst(Claims.Name)!.Value}.", "OK");
        }

        catch (OperationCanceledException)
        {
            await DisplayAlert("Authentication timed out", "The authentication process was aborted.", "OK");
        }

        catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
        {
            await DisplayAlert("Authorization denied", "The authorization was denied by the end user.", "OK");
        }

        catch
        {
            await DisplayAlert("Authentication failed", "An error occurred while trying to authenticate the user.", "OK");
        }
    }
}
