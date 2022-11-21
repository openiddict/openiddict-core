using Quartz;
using Xunit;

namespace OpenIddict.Quartz.Tests;

public class OpenIddictQuartzConfigurationTests
{
    [Fact]
    public void UseQuartz_RegistersJobDetails()
    {
        // Arrange
        var options = new QuartzOptions();
        var configuration = new OpenIddictQuartzConfiguration();

        // Act
        configuration.Configure(options);

        // Assert
        Assert.Equal(1, options.JobDetails.Count);
        Assert.Equal(OpenIddictQuartzJob.Identity, options.JobDetails[0].Key);
        Assert.Equal(SR.GetResourceString(SR.ID8003), options.JobDetails[0].Key.Name);
        Assert.Equal(SR.GetResourceString(SR.ID8005), options.JobDetails[0].Key.Group);
        Assert.Equal(SR.GetResourceString(SR.ID8001), options.JobDetails[0].Description);
    }

    [Fact]
    public void UseQuartz_RegistersTriggerDetails()
    {
        // Arrange
        var options = new QuartzOptions();
        var configuration = new OpenIddictQuartzConfiguration();

        // Act
        configuration.Configure(options);

        // Assert
        Assert.Equal(1, options.Triggers.Count);
        Assert.Equal(OpenIddictQuartzJob.Identity, options.Triggers[0].JobKey);
        Assert.Equal(SR.GetResourceString(SR.ID8004), options.Triggers[0].Key.Name);
        Assert.Equal(SR.GetResourceString(SR.ID8005), options.Triggers[0].Key.Group);
        Assert.Equal(SR.GetResourceString(SR.ID8002), options.Triggers[0].Description);
    }
}
