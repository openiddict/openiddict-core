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
        Assert.Contains(options.JobDetails, job => job.Key.Equals(OpenIddictQuartzJob.Identity));
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
        Assert.Contains(options.Triggers, trigger => trigger.JobKey.Equals(OpenIddictQuartzJob.Identity));
    }
}
