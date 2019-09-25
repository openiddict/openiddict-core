/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.IO;
using System.Security.Claims;
using JetBrains.Annotations;

namespace OpenIddict.Server.DataProtection
{
    public interface IOpenIddictServerDataProtectionFormatter
    {
        ClaimsPrincipal ReadToken([NotNull] BinaryReader reader);
        void WriteToken([NotNull] BinaryWriter writer, [NotNull] ClaimsPrincipal principal);
    }
}