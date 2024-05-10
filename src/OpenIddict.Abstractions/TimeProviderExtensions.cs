/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Abstractions;

public static class TimeProviderExtensions
{
    public static DateTimeOffset GetUtcNow<T>(this T option) where T : IOptionWithTimeProvider
    {
#if SUPPORTS_TIME_PROVIDER
        return option.TimeProvider!.GetUtcNow();
#else
        return DateTimeOffset.UtcNow;
#endif
    }
}
