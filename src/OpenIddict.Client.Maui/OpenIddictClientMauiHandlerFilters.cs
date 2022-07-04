/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Client.Maui;

/// <summary>
/// Contains a collection of event handler filters commonly used by the MAUI handlers.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictClientMauiHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers if no MAUI application context can be found.
    /// </summary>
    public class RequireMauiApplication : IOpenIddictClientHandlerFilter<BaseContext>
    {
        private readonly IApplication? _application;

        /// <summary>
        /// Creates a new instance of the <see cref="RequireMauiApplication"/> class.
        /// </summary>
        public RequireMauiApplication()
        {
        }

        /// <summary>
        /// Creates a new instance of the <see cref="RequireMauiApplication"/> class.
        /// </summary>
        /// <param name="application">The MAUI application instance.</param>
        /// <exception cref="ArgumentNullException"><paramref name="application"/> is <see langword="null"/>.</exception>
        public RequireMauiApplication(IApplication application)
            => _application = application ?? throw new ArgumentNullException(nameof(application));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_application is not null);
        }
    }
}
