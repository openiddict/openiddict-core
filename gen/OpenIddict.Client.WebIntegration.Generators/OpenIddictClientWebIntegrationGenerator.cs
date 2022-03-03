using System.Text;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Scriban;

namespace OpenIddict.Client.WebIntegration.Generators
{
    [Generator]
    public class OpenIddictClientWebIntegrationGenerator : ISourceGenerator
    {
        public void Execute(GeneratorExecutionContext context)
        {
            var file = context.AdditionalFiles.Select(file => file.Path)
                .Where(path => string.Equals(Path.GetFileName(path), "OpenIddictClientWebIntegrationProviders.xml"))
                .SingleOrDefault();

            if (string.IsNullOrEmpty(file))
            {
                return;
            }

            var document = XDocument.Load(file, LoadOptions.None);

            context.AddSource(
                "OpenIddictClientWebIntegrationBuilder.generated.cs",
                SourceText.From(GenerateBuilderMethods(document), Encoding.UTF8));

            context.AddSource(
                "OpenIddictClientWebIntegrationConstants.generated.cs",
                SourceText.From(GenerateConstants(document), Encoding.UTF8));

            context.AddSource(
                "OpenIddictClientWebIntegrationSettings.generated.cs",
                SourceText.From(GenerateSettings(document), Encoding.UTF8));

            static string GenerateBuilderMethods(XDocument document)
            {
                var template = Template.Parse(@"#nullable enable

using OpenIddict.Client;
using OpenIddict.Client.WebIntegration;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;
using Properties = OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants.Properties;

namespace Microsoft.Extensions.DependencyInjection;

public partial class OpenIddictClientWebIntegrationBuilder
{
    {{~ for provider in providers ~}}
    /// <summary>
    /// Enables {{ provider.name }} integration using the specified settings.
    /// </summary>
    /// <param name=""settings"">The provider settings.</param>
    /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder""/>.</returns>
    public OpenIddictClientWebIntegrationBuilder Add{{ provider.name }}(
        OpenIddictClientWebIntegrationSettings.{{ provider.name }}Settings settings!!)
    {
        Services.Configure<OpenIddictClientOptions>(options =>
        {
            var registration = new OpenIddictClientRegistration
            {
                Issuer = new Uri(""{{ provider.issuer }}"", UriKind.Absolute),

                ClientId = settings.ClientId,
                ClientSecret = settings.ClientSecret,
                RedirectUri = settings.RedirectUri,

                {{~ if provider.configuration ~}}
                Configuration = new OpenIddictConfiguration
                {
                    {{~ if provider.configuration.authorization_endpoint ~}}
                    AuthorizationEndpoint = new Uri(""{{ provider.configuration.authorization_endpoint }}"", UriKind.Absolute),
                    {{~ end ~}}

                    {{~ if provider.configuration.token_endpoint ~}}
                    TokenEndpoint = new Uri(""{{ provider.configuration.token_endpoint }}"", UriKind.Absolute),
                    {{~ end ~}}

                    {{~ if provider.configuration.userinfo_endpoint ~}}
                    UserinfoEndpoint = new Uri(""{{ provider.configuration.userinfo_endpoint }}"", UriKind.Absolute),
                    {{~ end ~}}

                    {{~ if provider.configuration.grant_types_supported ~}}
                    GrantTypesSupported =
                    {
                        {{~ for type in provider.configuration.grant_types_supported ~}}
                        ""{{ type }}""
                        {{~ end ~}}
                    },
                    {{~ end ~}}

                    {{~ if provider.configuration.response_types_supported ~}}
                    ResponseTypesSupported =
                    {
                        {{~ for type in provider.configuration.response_types_supported ~}}
                        ""{{ type }}""
                        {{~ end ~}}
                    },
                    {{~ end ~}}

                    {{~ if provider.configuration.response_modes_supported ~}}
                    ResponseModesSupported =
                    {
                        {{~ for mode in provider.configuration.response_modes_supported ~}}
                        ""{{ mode }}""
                        {{~ end ~}}
                    },
                    {{~ end ~}}
                },
                {{~ end ~}}

                Properties =
                {
                    [Properties.ProviderName] = Providers.{{ provider.name }},

                    {{~ for setting in provider.settings ~}}
                    [""{{ setting.property }}""] = settings.{{ setting.name }},

                    {{~ end ~}}
                }
            };

            registration.Scopes.UnionWith(settings.Scopes);

            options.Registrations.Add(registration);
        });

        return this;
    }
    {{~ end ~}}
}
");
                return template.Render(new
                {
                    Providers = document.Root.Descendants("Provider")
                        .Select(provider => new
                        {
                            Issuer = provider.Attribute("Issuer")?.Value,
                            Name = provider.Attribute("Name")?.Value,
                            Configuration = provider.Element("Configuration") switch
                            {
                                XElement configuration => new
                                {
                                    AuthorizationEndpoint = configuration.Attribute("AuthorizationEndpoint")?.Value,
                                    TokenEndpoint = configuration.Attribute("TokenEndpoint")?.Value,
                                    UserinfoEndpoint = configuration.Attribute("UserinfoEndpoint")?.Value,

                                    GrantTypesSupported = configuration.Attribute("GrantTypesSupported")?.Value switch
                                    {
                                        string value => value.Split(new[] { "," }, StringSplitOptions.RemoveEmptyEntries),
                                        _ => null
                                    },

                                    ResponseTypesSupported = configuration.Attribute("ResponseTypesSupported")?.Value switch
                                    {
                                        string value => value.Split(new[] { "," }, StringSplitOptions.RemoveEmptyEntries),
                                        _ => null
                                    },

                                    ResponseModesSupported = configuration.Attribute("ResponseModesSupported")?.Value switch
                                    {
                                        string value => value.Split(new[] { "," }, StringSplitOptions.RemoveEmptyEntries),
                                        _ => null
                                    },
                                },
                                _ => null
                            },

                            Settings = provider.Descendants("Setting").Select(setting => new
                            {
                                Name = setting.Attribute("Name")?.Value,
                                Property = setting.Attribute("Property")?.Value
                            })
                        })
                        .ToList()
                });
            }

            static string GenerateConstants(XDocument document)
            {
                var template = Template.Parse(@"#nullable enable

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationConstants
{
    public static class Providers
    {
        {{~ for provider in providers ~}}
        public const string {{ provider.name }} = ""{{ provider.name }}"";
        {{~ end ~}}
    }
}
");
                return template.Render(new
                {
                    Providers = document.Root.Descendants("Provider")
                        .Select(provider => new { Name = provider.Attribute("Name")?.Value })
                        .ToList()
                });
            }

            static string GenerateSettings(XDocument document)
            {
                var template = Template.Parse(@"#nullable enable

namespace OpenIddict.Client.WebIntegration;

public partial class OpenIddictClientWebIntegrationSettings
{
    {{~ for provider in providers ~}}
    /// <summary>
    /// Provides various settings needed to configure the {{ provider.name }} integration.
    /// </summary>
    public class {{ provider.name }}Settings : OpenIddictClientWebIntegrationSettings
    {
        {{~ for setting in provider.settings ~}}
        {{~ if setting.description ~}}
        /// <summary>
        /// {{ setting.description }}
        /// </summary>
        {{~ end ~}}
        public {{ setting.type }}? {{ setting.name }} { get; set; }

        {{~ end ~}}
    }
    {{~ end ~}}
}
");
                return template.Render(new
                {
                    Providers = document.Root.Descendants("Provider")
                        .Select(provider => new
                        {
                            Name = provider.Attribute("Name")?.Value,

                            Settings = provider.Descendants("Setting").Select(setting => new
                            {
                                Type = setting.Attribute("Type")?.Value,
                                Name = setting.Attribute("Name")?.Value,
                                Property = setting.Attribute("Property")?.Value,
                                Description = setting.Attribute("Description")?.Value
                            })
                        })
                        .ToList()
                });
            }
        }

        public void Initialize(GeneratorInitializationContext context)
        {
        }
    }
}
