//#if IOS || MACCATALYST || WINDOWS
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Maui.Hosting;
using System;

namespace OpenIddict.Sandbox.Maui.Client;

public class Worker : IMauiInitializeScopedService
{
    public void Initialize(IServiceProvider services)
    {
        var context = services.GetRequiredService<DbContext>();
        context.Database.EnsureCreated();
    }
}
//#endif
