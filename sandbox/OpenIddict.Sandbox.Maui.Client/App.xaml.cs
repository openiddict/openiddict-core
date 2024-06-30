#if IOS || MACCATALYST || WINDOWS
namespace OpenIddict.Sandbox.Maui.Client;

public partial class App : Application
{
    public App()
    {
        InitializeComponent();

        MainPage = new AppShell();
    }
}
#endif
