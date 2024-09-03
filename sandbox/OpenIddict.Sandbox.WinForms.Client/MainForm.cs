using Dapplo.Microsoft.Extensions.Hosting.WinForms;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Sandbox.WinForms.Client;

public partial class MainForm : Form, IWinFormsShell
{
    private readonly OpenIddictClientService _service;

    public MainForm(OpenIddictClientService service)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));

        InitializeComponent();
    }

    private async void LocalLoginButton_Click(object sender, EventArgs e)
        => await LogInAsync("Local");

    private async void LocalLoginWithGitHubButton_Click(object sender, EventArgs e)
        => await LogInAsync("Local", new()
        {
            [Parameters.IdentityProvider] = Providers.GitHub
        });

    private async void LocalLogoutButton_Click(object sender, EventArgs e)
        => await LogOutAsync("Local");

    private async void GitHubLoginButton_Click(object sender, EventArgs e)
        => await LogInAsync(Providers.GitHub);

    private async Task LogInAsync(string provider, Dictionary<string, OpenIddictParameter>? parameters = null)
    {
        // Disable the buttons to prevent concurrent operations.
        LocalLogin.Enabled = false;
        LocalLoginWithGitHub.Enabled = false;
        LocalLogout.Enabled = false;
        GitHubLogin.Enabled = false;

        try
        {
            using var source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(90));

            try
            {
                // Ask OpenIddict to initiate the authentication flow (typically, by starting the system browser).
                var result = await _service.ChallengeInteractivelyAsync(new()
                {
                    AdditionalAuthorizationRequestParameters = parameters,
                    CancellationToken = source.Token,
                    ProviderName = provider
                });

                // Wait for the user to complete the authorization process.
                var principal = (await _service.AuthenticateInteractivelyAsync(new()
                {
                    CancellationToken = source.Token,
                    Nonce = result.Nonce
                })).Principal;

#if SUPPORTS_WINFORMS_TASK_DIALOG
                TaskDialog.ShowDialog(new TaskDialogPage
                {
                    Caption = "Authentication successful",
                    Heading = "Authentication successful",
                    Icon = TaskDialogIcon.ShieldSuccessGreenBar,
                    Text = $"Welcome, {principal.FindFirst(Claims.Name)!.Value}."
                });
#else
                MessageBox.Show($"Welcome, {principal.FindFirst(Claims.Name)!.Value}.",
                    "Authentication successful", MessageBoxButtons.OK, MessageBoxIcon.Information);
#endif
            }

            catch (OperationCanceledException)
            {
#if SUPPORTS_WINFORMS_TASK_DIALOG
                TaskDialog.ShowDialog(new TaskDialogPage
                {
                    Caption = "Authentication timed out",
                    Heading = "Authentication timed out",
                    Icon = TaskDialogIcon.Warning,
                    Text = "The authentication process was aborted."
                });
#else
                MessageBox.Show("The authentication process was aborted.",
                    "Authentication timed out", MessageBoxButtons.OK, MessageBoxIcon.Warning);
#endif
            }

            catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
            {
#if SUPPORTS_WINFORMS_TASK_DIALOG
                TaskDialog.ShowDialog(new TaskDialogPage
                {
                    Caption = "Authorization denied",
                    Heading = "Authorization denied",
                    Icon = TaskDialogIcon.Warning,
                    Text = "The authorization was denied by the end user."
                });
#else
                MessageBox.Show("The authorization was denied by the end user.",
                    "Authorization denied", MessageBoxButtons.OK, MessageBoxIcon.Warning);
#endif
            }

            catch
            {
#if SUPPORTS_WINFORMS_TASK_DIALOG
                TaskDialog.ShowDialog(new TaskDialogPage
                {
                    Caption = "Authentication failed",
                    Heading = "Authentication failed",
                    Icon = TaskDialogIcon.Error,
                    Text = "An error occurred while trying to authenticate the user."
                });
#else
                MessageBox.Show("An error occurred while trying to authenticate the user.",
                    "Authentication failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
#endif
            }
        }

        finally
        {
            // Re-enable the buttons to allow starting a new operation.
            LocalLogin.Enabled = true;
            LocalLoginWithGitHub.Enabled = true;
            LocalLogout.Enabled = true;
            GitHubLogin.Enabled = true;
        }
    }

    private async Task LogOutAsync(string provider, Dictionary<string, OpenIddictParameter>? parameters = null)
    {
        // Disable the buttons to prevent concurrent operations.
        LocalLogin.Enabled = false;
        LocalLoginWithGitHub.Enabled = false;
        LocalLogout.Enabled = false;
        GitHubLogin.Enabled = false;

        try
        {
            using var source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(90));

            try
            {
                // Ask OpenIddict to initiate the logout flow (typically, by starting the system browser).
                var result = await _service.SignOutInteractivelyAsync(new()
                {
                    AdditionalEndSessionRequestParameters = parameters,
                    CancellationToken = source.Token,
                    ProviderName = provider
                });

                // Wait for the user to complete the logout process and authenticate the callback request.
                //
                // Note: in this case, only the claims contained in the state token can be resolved since
                // the authorization server doesn't return any other user identity during a logout dance.
                await _service.AuthenticateInteractivelyAsync(new()
                {
                    CancellationToken = source.Token,
                    Nonce = result.Nonce
                });

#if SUPPORTS_WINFORMS_TASK_DIALOG
                TaskDialog.ShowDialog(new TaskDialogPage
                {
                    Caption = "Logout successful",
                    Heading = "Logout successful",
                    Icon = TaskDialogIcon.ShieldSuccessGreenBar,
                    Text = "The user was successfully logged out from the local server."
                });
#else
                MessageBox.Show("The user was successfully logged out from the local server.",
                    "Logout successful", MessageBoxButtons.OK, MessageBoxIcon.Information);
#endif
            }

            catch (OperationCanceledException)
            {
#if SUPPORTS_WINFORMS_TASK_DIALOG
                TaskDialog.ShowDialog(new TaskDialogPage
                {
                    Caption = "Logout timed out",
                    Heading = "Logout timed out",
                    Icon = TaskDialogIcon.Warning,
                    Text = "The logout process was aborted."
                });
#else
                MessageBox.Show("The authentication process was aborted.",
                    "Logout timed out", MessageBoxButtons.OK, MessageBoxIcon.Warning);
#endif
            }

            catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
            {
#if SUPPORTS_WINFORMS_TASK_DIALOG
                TaskDialog.ShowDialog(new TaskDialogPage
                {
                    Caption = "Logout denied",
                    Heading = "Logout denied",
                    Icon = TaskDialogIcon.Warning,
                    Text = "The logout demand was denied by the end user."
                });
#else
                MessageBox.Show("The logout demand was denied by the end user.",
                    "Logout denied", MessageBoxButtons.OK, MessageBoxIcon.Warning);
#endif
            }

            catch
            {
#if SUPPORTS_WINFORMS_TASK_DIALOG
                TaskDialog.ShowDialog(new TaskDialogPage
                {
                    Caption = "Logout failed",
                    Heading = "Logout failed",
                    Icon = TaskDialogIcon.Error,
                    Text = "An error occurred while trying to log the user out."
                });
#else
                MessageBox.Show("An error occurred while trying to log the user out.",
                    "Logout failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
#endif
            }
        }

        finally
        {
            // Re-enable the buttons to allow starting a new operation.
            LocalLogin.Enabled = true;
            LocalLoginWithGitHub.Enabled = true;
            LocalLogout.Enabled = true;
            GitHubLogin.Enabled = true;
        }
    }
}