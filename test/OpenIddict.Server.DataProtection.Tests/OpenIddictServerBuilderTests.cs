using System.Security.Claims;
using Xunit;

namespace OpenIddict.Server.DataProtection.Tests;

public class OpenIddictServerDataProtectionFormatterTests 
{
    [Fact]
    public void WriteToken_ReadToken_WithEmptyClaimsPrincipal()
    {
        // Arrange
        var services = new OpenIddictServerDataProtectionFormatter();
        
        using var buffer = new MemoryStream();
        using var writer = new BinaryWriter(buffer);

        var principal = new ClaimsPrincipal();

        // Act and assert
        services.WriteToken(writer, principal);

        buffer.Seek(0, SeekOrigin.Begin);
        
        using var reader = new BinaryReader(buffer);

        var deserializedClaimsPrincipal = services.ReadToken(reader);
        
        Assert.NotNull(deserializedClaimsPrincipal);
    }
}
