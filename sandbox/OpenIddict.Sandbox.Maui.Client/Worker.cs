#if IOS || MACCATALYST || WINDOWS
using Microsoft.EntityFrameworkCore;

namespace OpenIddict.Sandbox.Maui.Client;

public class Worker : IMauiInitializeScopedService
{
    public void Initialize(IServiceProvider services)
    {
        var context = services.GetRequiredService<DbContext>();
        context.Database.EnsureCreated();
    }
}
#endif
