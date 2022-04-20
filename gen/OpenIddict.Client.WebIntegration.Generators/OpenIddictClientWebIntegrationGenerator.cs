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
                "OpenIddictClientWebIntegrationEnvironments.generated.cs",
                SourceText.From(GenerateEnvironments(document), Encoding.UTF8));

            context.AddSource(
                "OpenIddictClientWebIntegrationSettings.generated.cs",
                SourceText.From(GenerateSettings(document), Encoding.UTF8));

            static string GenerateBuilderMethods(XDocument document)
            {
                var template = Template.Parse(@"#nullable enable

using OpenIddict.Client;
using OpenIddict.Client.WebIntegration;
using SmartFormat;
using SmartFormat.Core.Settings;
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
    public OpenIddictClientWebIntegrationBuilder Add{{ provider.name }}(OpenIddictClientWebIntegrationSettings.{{ provider.name }} settings)
    {
        if (settings is null)
        {
            throw new ArgumentNullException(nameof(settings));
        }

        Services.Configure<OpenIddictClientOptions>(options =>
        {
            var formatter = Smart.CreateDefaultSmartFormat(new SmartSettings
            {
                CaseSensitivity = CaseSensitivityType.CaseInsensitive
            });

            var registration = new OpenIddictClientRegistration
            {
                Issuer = settings.Environment switch
                {
                    {{~ for environment in provider.environments ~}}
                    OpenIddictClientWebIntegrationEnvironments.{{ provider.name }}.{{ environment.name }}
                        => new Uri(formatter.Format(""{{ environment.issuer }}"", settings), UriKind.Absolute),
                    {{~ end ~}}

                    _ => throw new InvalidOperationException(SR.FormatID0194(nameof(settings.Environment)))
                },

                ClientId = settings.ClientId,
                ClientSecret = settings.ClientSecret,
                RedirectUri = settings.RedirectUri,

                Configuration = settings.Environment switch
                {
                    {{~ for environment in provider.environments ~}}
                    {{~ if environment.configuration ~}}
                    OpenIddictClientWebIntegrationEnvironments.{{ provider.name }}.{{ environment.name }} => new OpenIddictConfiguration
                    {
                        {{~ if environment.configuration.authorization_endpoint ~}}
                        AuthorizationEndpoint = new Uri(formatter.Format(""{{ environment.configuration.authorization_endpoint }}"", settings), UriKind.Absolute),
                        {{~ end ~}}

                        {{~ if environment.configuration.token_endpoint ~}}
                        TokenEndpoint = new Uri(formatter.Format(""{{ environment.configuration.token_endpoint }}"", settings), UriKind.Absolute),
                        {{~ end ~}}

                        {{~ if environment.configuration.userinfo_endpoint ~}}
                        UserinfoEndpoint = new Uri(formatter.Format(""{{ environment.configuration.userinfo_endpoint }}"", settings), UriKind.Absolute),
                        {{~ end ~}}

                        CodeChallengeMethodsSupported =
                        {
                            {{~ for method in environment.configuration.code_challenge_methods_supported ~}}
                            ""{{ method }}"",
                            {{~ end ~}}
                        },

                        GrantTypesSupported =
                        {
                            {{~ for type in environment.configuration.grant_types_supported ~}}
                            ""{{ type }}"",
                            {{~ end ~}}
                        },

                        ResponseModesSupported =
                        {
                            {{~ for mode in environment.configuration.response_modes_supported ~}}
                            ""{{ mode }}"",
                            {{~ end ~}}
                        },

                        ResponseTypesSupported =
                        {
                            {{~ for type in environment.configuration.response_types_supported ~}}
                            ""{{ type }}"",
                            {{~ end ~}}
                        },

                        ScopesSupported =
                        {
                            {{~ for scope in environment.configuration.scopes_supported ~}}
                            ""{{ scope }}"",
                            {{~ end ~}}
                        },

                        TokenEndpointAuthMethodsSupported =
                        {
                            {{~ for method in environment.configuration.token_endpoint_auth_methods_supported ~}}
                            ""{{ method }}"",
                            {{~ end ~}}
                        }
                    },
                    {{~ else ~}}
                    OpenIddictClientWebIntegrationEnvironments.{{ provider.name }}.{{ environment.name }} => null,
                    {{~ end ~}}
                    {{~ end ~}}

                    _ => throw new InvalidOperationException(SR.FormatID0194(nameof(settings.Environment)))
                },

                Properties =
                {
                    [Properties.ProviderName] = OpenIddictClientWebIntegrationConstants.Providers.{{ provider.name }},

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
                    Providers = document.Root.Elements("Provider")
                        .Select(provider => new
                        {
                            Name = (string?) provider.Attribute("Name"),

                            Environments = provider.Elements("Environment").Select(environment => new
                            {
                                Name = (string?) environment.Attribute("Name") ?? "Production",
                                Issuer = (string?) environment.Attribute("Issuer"),
                                Configuration = environment.Element("Configuration") switch
                                {
                                    XElement configuration => new
                                    {
                                        AuthorizationEndpoint = (string?) configuration.Attribute("AuthorizationEndpoint"),
                                        TokenEndpoint = (string?) configuration.Attribute("TokenEndpoint"),
                                        UserinfoEndpoint = (string?) configuration.Attribute("UserinfoEndpoint"),

                                        CodeChallengeMethodsSupported = configuration.Elements("CodeChallengeMethod").ToList() switch
                                        {
                                            { Count: > 0 } methods => methods.Select(type => (string?) type.Attribute("Value")).ToList(),

                                            _ => (IList<string>) Array.Empty<string>()
                                        },

                                        GrantTypesSupported = configuration.Elements("GrantType").ToList() switch
                                        {
                                            { Count: > 0 } types => types.Select(type => (string?) type.Attribute("Value")).ToList(),

                                            // If no explicit grant type was set, assume the provider only supports the code flow.
                                            _ => (IList<string>) new[] { GrantTypes.AuthorizationCode }
                                        },

                                        ResponseModesSupported = configuration.Elements("ResponseMode").ToList() switch
                                        {
                                            { Count: > 0 } modes => modes.Select(type => (string?) type.Attribute("Value")).ToList(),

                                            // If no explicit response mode was set, assume the provider only supports the query response mode.
                                            _ => (IList<string>) new[] { ResponseModes.Query }
                                        },

                                        ResponseTypesSupported = configuration.Elements("ResponseType").ToList() switch
                                        {
                                            { Count: > 0 } types => types.Select(type => (string?) type.Attribute("Value")).ToList(),

                                            // If no explicit response type was set, assume the provider only supports the code flow.
                                            _ => (IList<string>) new[] { ResponseTypes.Code }
                                        },

                                        ScopesSupported = configuration.Elements("Scope").ToList() switch
                                        {
                                            { Count: > 0 } types => types.Select(type => (string?) type.Attribute("Value")).ToList(),

                                            _ => (IList<string>) Array.Empty<string>()
                                        },

                                        TokenEndpointAuthMethodsSupported = configuration.Elements("TokenEndpointAuthMethod").ToList() switch
                                        {
                                            { Count: > 0 } methods => methods.Select(type => (string?) type.Attribute("Value")).ToList(),

                                            // If no explicit response type was set, assume the provider only supports
                                            // flowing the client credentials as part of the token request payload.
                                            _ => (IList<string>) new[] { ClientAuthenticationMethods.ClientSecretPost }
                                        }
                                    },

                                    _ => null
                                }
                            })
                            .ToList(),

                            Settings = provider.Elements("Setting").Select(setting => new
                            {
                                Name = (string?) setting.Attribute("Name"),
                                Property = (string?) setting.Attribute("Property")
                            })
                            .ToList()
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
                    Providers = document.Root.Elements("Provider")
                        .Select(provider => new { Name = (string?) provider.Attribute("Name") })
                        .ToList()
                });
            }

            static string GenerateEnvironments(XDocument document)
            {
                var template = Template.Parse(@"#nullable enable

namespace OpenIddict.Client.WebIntegration;

public partial class OpenIddictClientWebIntegrationEnvironments
{
    {{~ for provider in providers ~}}
    /// <summary>
    /// Exposes the environments supported by the {{ provider.name }} provider.
    /// </summary>
    public enum {{ provider.name }}
    {
        {{~ for environment in provider.environments ~}}
        {{ environment.name }},
        {{~ end ~}}
    }
    {{~ end ~}}
}
");
                return template.Render(new
                {
                    Providers = document.Root.Elements("Provider")
                        .Select(provider => new
                        {
                            Name = (string?) provider.Attribute("Name"),

                            Environments = provider.Elements("Environment").Select(environment => new
                            {
                                Name = (string?) environment.Attribute("Name") ?? "Production"
                            })
                            .ToList()
                        })
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
    public class {{ provider.name }} : OpenIddictClientWebIntegrationSettings
    {
        {{~ for setting in provider.settings ~}}
        {{~ if setting.description ~}}
        /// <summary>
        /// {{ setting.description }}
        /// </summary>
        {{~ end ~}}
        public {{ setting.type }}? {{ setting.name }} { get; set; }

        {{~ end ~}}

        /// <summary>
        /// Gets or sets the environment that determines the endpoints to use.
        /// </summary>
        public OpenIddictClientWebIntegrationEnvironments.{{ provider.name }} Environment { get; set; }
    }
    {{~ end ~}}
}
");
                return template.Render(new
                {
                    Providers = document.Root.Elements("Provider")
                        .Select(provider => new
                        {
                            Name = (string?) provider.Attribute("Name"),

                            Settings = provider.Elements("Setting").Select(setting => new
                            {
                                Type = (string?) setting.Attribute("Type"),
                                Name = (string?) setting.Attribute("Name"),
                                Property = (string?) setting.Attribute("Property"),
                                Description = (string?) setting.Attribute("Description")
                            })
                            .ToList()
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
