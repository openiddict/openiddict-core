/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Reflection;
using JetBrains.Annotations;
using Microsoft.Extensions.FileProviders;

namespace Microsoft.AspNetCore.Builder {
    public static class OpenIddictExtensions {
        public static OpenIddictBuilder UseAssets([NotNull] this OpenIddictBuilder builder) {
            if (builder == null) {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddModule("Assets", -20, app => app.UseStaticFiles(new StaticFileOptions {
                FileProvider = new EmbeddedFileProvider(
                    assembly: Assembly.Load(new AssemblyName("OpenIddict.Assets")),
                    baseNamespace: "OpenIddict.Assets")
            }));
        }
    }
}