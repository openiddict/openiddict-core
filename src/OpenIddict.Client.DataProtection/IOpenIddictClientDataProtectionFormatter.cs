/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;

namespace OpenIddict.Client.DataProtection;

public interface IOpenIddictClientDataProtectionFormatter
{
    ClaimsPrincipal ReadToken(BinaryReader reader);
    void WriteToken(BinaryWriter writer, ClaimsPrincipal principal);
}
