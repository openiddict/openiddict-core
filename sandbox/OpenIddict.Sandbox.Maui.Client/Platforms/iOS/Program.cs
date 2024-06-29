#if IOS
using ObjCRuntime;
using UIKit;

namespace OpenIddict.Sandbox.Maui.Client;

public static class Program
{
    public static void Main(string[] args) => UIApplication.Main(args, null, typeof(AppDelegate));
}
#endif
