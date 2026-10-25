using System.Globalization;
using System.Text;
using System.Xml.Linq;
using Fluid;
using Fluid.SourceGenerator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace OpenIddict.Client.WebIntegration.Generators;

[Generator]
public sealed class OpenIddictClientWebIntegrationGenerator : IIncrementalGenerator
{
    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        var files = context.AdditionalTextsProvider.Where(static file =>
            string.Equals(Path.GetFileName(file.Path), "OpenIddictClientWebIntegrationProviders.xml", StringComparison.OrdinalIgnoreCase));

        context.RegisterSourceOutput(files, static (context, file) =>
        {
            var parser = new FluidParser();
            var options = new TemplateOptions
            {
                ModelNamesComparer = StringComparers.SnakeCase
            };

            var document = XDocument.Load(file.Path, LoadOptions.None);

            context.AddSource(
                "OpenIddictClientWebIntegrationBuilder.generated.cs",
                SourceText.From(GenerateBuilderMethods(parser, options, document, context.CancellationToken), Encoding.UTF8));

            context.AddSource(
                "OpenIddictClientWebIntegrationConfiguration.generated.cs",
                SourceText.From(GenerateConfigurationClasses(parser, options, document, context.CancellationToken), Encoding.UTF8));

            context.AddSource(
                "OpenIddictClientWebIntegrationConstants.generated.cs",
                SourceText.From(GenerateConstants(parser, options, document, context.CancellationToken), Encoding.UTF8));

            context.AddSource(
                "OpenIddictClientWebIntegrationHelpers.generated.cs",
                SourceText.From(GenerateHelpers(parser, options, document, context.CancellationToken), Encoding.UTF8));

            context.AddSource(
                "OpenIddictClientWebIntegrationSettings.generated.cs",
                SourceText.From(GenerateSettings(parser, options, document, context.CancellationToken), Encoding.UTF8));
        });

        static string GenerateBuilderMethods(FluidParser parser, TemplateOptions options, XDocument document, CancellationToken cancellationToken)
        {
            var model = new
            {
                Providers = document.Root.Elements("Provider")
                    .Select(static provider => new
                    {
                        Name = (string) provider.Attribute("Name"),
                        DisplayName = (string?) provider.Attribute("DisplayName") ?? (string) provider.Attribute("Name"),
                        Documentation = (string?) provider.Attribute("Documentation"),

                        Obsolete = (bool?) provider.Attribute("Obsolete") ?? false,

                        Environments = provider.Elements("Environment").Select(static environment => new
                        {
                            Name = (string?) environment.Attribute("Name") ?? "Production"
                        })
                        .ToList(),

                        Settings = provider.Elements("Setting").Select(static setting => new
                        {
                            PropertyName = (string) setting.Attribute("PropertyName"),
                            ParameterName = (string) setting.Attribute("ParameterName"),

                            Collection = (bool?) setting.Attribute("Collection") ?? false,
                            Obsolete = (bool?) setting.Attribute("Obsolete") ?? false,

                            Description = (string) setting.Attribute("Description") is string description
                                ? $"{char.ToLower(description[0], CultureInfo.GetCultureInfo("en-US"))}{description[1..]}"
                                : null,
                            ClrType = (string) setting.Attribute("Type") switch
                            {
                                "Boolean" => "bool",
                                "EncryptionKey" => (string?) setting.Element("EncryptionAlgorithm")?.Attribute("Value") switch
                                {
                                    "RS256" or "RS384" or "RS512" => "RsaSecurityKey",

                                    _ => "SecurityKey"
                                },

                                "SigningCertificate" => "X509Certificate2",

                                "SigningKey" => (string?) setting.Element("SigningAlgorithm")?.Attribute("Value") switch
                                {
                                    "ES256" or "ES384" or "ES512" => "ECDsaSecurityKey",
                                    "PS256" or "PS384" or "PS512" or "RS256" or "RS384" or "RS512" => "RsaSecurityKey",

                                    _ => "SecurityKey"
                                },

                                "String" => "string",
                                "StringHashSet" => "HashSet<string>",
                                "Uri" => "Uri",

                                string value => value
                            }
                        })
                        .ToList()
                    })
                    .ToList()
            };

            var context = new TemplateContext(model, options)
            {
                CancellationToken = cancellationToken
            };

            return Templates.OpenIddictClientWebIntegrationBuilder.Render(context);
        }

        static string GenerateConstants(FluidParser parser, TemplateOptions options, XDocument document, CancellationToken cancellationToken)
        {
            var model = new
            {
                Providers = document.Root.Elements("Provider")
                    .Select(static provider => new
                    {
                        Name = (string) provider.Attribute("Name"),
                        Id = (string) provider.Attribute("Id"),

                        Environments = provider.Elements("Environment").Select(static environment => new
                        {
                            Name = (string?) environment.Attribute("Name") ?? "Production"
                        })
                        .ToList(),

                        Properties = provider.Elements("Property").Select(static property => new
                        {
                            Name = (string) property.Attribute("Name"),
                            DictionaryKey = (string) property.Attribute("DictionaryKey")
                        })
                        .ToList(),

                        Constants = provider.Elements("Constant")
                            .Select(static constant => new
                            {
                                Class = (string) constant.Attribute("Class"),
                                Name = (string) constant.Attribute("Name"),
                                Value = (string) constant.Attribute("Value")
                            })
                            .GroupBy(static constant => constant.Class, StringComparer.Ordinal)
                            .Select(static group => new { Class = group.Key, Members = group.ToList() })
                            .ToList(),
                    })
                    .ToList()
            };

            var context = new TemplateContext(model, options)
            {
                CancellationToken = cancellationToken
            };

            return Templates.OpenIddictClientWebIntegrationConstants.Render(context);
        }

        static string GenerateConfigurationClasses(FluidParser parser, TemplateOptions options, XDocument document, CancellationToken cancellationToken)
        {
            var model = new
            {
                Providers = document.Root.Elements("Provider")
                    .Select(static provider => new
                    {
                        Name = (string) provider.Attribute("Name"),
                        DisplayName = (string?) provider.Attribute("DisplayName") ?? (string) provider.Attribute("Name"),

                        Environments = provider.Elements("Environment").Select(static environment => new
                        {
                            Name = (string?) environment.Attribute("Name") ?? "Production",

                            Issuer = (string) environment.Attribute("Issuer"),
                            ConfigurationEndpoint = (string?) environment.Attribute("ConfigurationEndpoint"),

                            Configuration = environment.Element("Configuration") switch
                            {
                                XElement configuration => new
                                {
                                    AuthorizationEndpoint = (string?) configuration.Attribute("AuthorizationEndpoint"),
                                    DeviceAuthorizationEndpoint = (string?) configuration.Attribute("DeviceAuthorizationEndpoint"),
                                    IntrospectionEndpoint = (string?) configuration.Attribute("IntrospectionEndpoint"),
                                    RevocationEndpoint = (string?) configuration.Attribute("RevocationEndpoint"),
                                    TokenEndpoint = (string?) configuration.Attribute("TokenEndpoint"),
                                    UserInfoEndpoint = (string?) configuration.Attribute("UserInfoEndpoint"),

                                    AuthorizationResponseIssParameterSupported = (bool?) configuration.Attribute("AuthorizationResponseIssParameterSupported"),

                                    CodeChallengeMethodsSupported = configuration.Elements("CodeChallengeMethod").ToList() switch
                                    {
                                        { Count: > 0 } methods => methods.Select(static type => (string?) type.Attribute("Value")).ToList(),

                                        _ => []
                                    },

                                    GrantTypesSupported = configuration.Elements("GrantType").ToList() switch
                                    {
                                        { Count: > 0 } types => types.Select(static type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit grant type was set, assume the provider only supports the code flow.
                                        _ => ["authorization_code"]
                                    },

                                    ResponseModesSupported = configuration.Elements("ResponseMode").ToList() switch
                                    {
                                        { Count: > 0 } modes => modes.Select(static type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit response mode was set, assume the provider only supports the query response mode.
                                        _ => ["query"]
                                    },

                                    ResponseTypesSupported = configuration.Elements("ResponseType").ToList() switch
                                    {
                                        { Count: > 0 } types => types.Select(static type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit response type was set, assume the provider only supports the code flow.
                                        _ => ["code"]
                                    },

                                    ScopesSupported = configuration.Elements("Scope").ToList() switch
                                    {
                                        { Count: > 0 } types => types.Select(static type => (string?) type.Attribute("Value")).ToList(),

                                        _ => []
                                    },

                                    DeviceAuthorizationEndpointAuthMethodsSupported = configuration.Elements("DeviceAuthorizationEndpointAuthMethod").ToList() switch
                                    {
                                        { Count: > 0 } methods => methods.Select(static type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit client authentication method was set, assume the provider only supports
                                        // flowing the client credentials as part of the device authorization request payload.
                                        _ => ["client_secret_post"]
                                    },

                                    IntrospectionEndpointAuthMethodsSupported = configuration.Elements("IntrospectionEndpointAuthMethod").ToList() switch
                                    {
                                        { Count: > 0 } methods => methods.Select(static type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit client authentication method was set, assume the provider only
                                        // supports flowing the client credentials as part of the introspection request payload.
                                        _ => ["client_secret_post"]
                                    },

                                    RevocationEndpointAuthMethodsSupported = configuration.Elements("RevocationEndpointAuthMethod").ToList() switch
                                    {
                                        { Count: > 0 } methods => methods.Select(static type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit client authentication method was set, assume the provider only
                                        // supports flowing the client credentials as part of the revocation request payload.
                                        _ => ["client_secret_post"]
                                    },

                                    TokenEndpointAuthMethodsSupported = configuration.Elements("TokenEndpointAuthMethod").ToList() switch
                                    {
                                        { Count: > 0 } methods => methods.Select(static type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit client authentication method was set, assume the provider only
                                        // supports flowing the client credentials as part of the token request payload.
                                        _ => ["client_secret_post"]
                                    }
                                },

                                _ => null
                            },

                            Scopes = environment.Elements("Scope").Select(static setting => new
                            {
                                Name = (string) setting.Attribute("Name"),
                                Default = (bool?) setting.Attribute("Default") ?? false,
                                Required = (bool?) setting.Attribute("Required") ?? false
                            })
                        })
                        .ToList(),

                        Settings = provider.Elements("Setting").Select(static setting => new
                        {
                            PropertyName = (string) setting.Attribute("PropertyName"),

                            Type = (string) setting.Attribute("Type"),
                            Required = (bool?) setting.Attribute("Required") ?? false,
                            Collection = (bool?) setting.Attribute("Collection") ?? false,

                            EncryptionAlgorithm = (string?) setting.Element("EncryptionAlgorithm")?.Attribute("Value"),
                            SigningAlgorithm = (string?) setting.Element("SigningAlgorithm")?.Attribute("Value"),

                            DefaultValue = (string?) setting.Attribute("DefaultValue"),

                            Items = setting.Elements("Item").Select(static item => new
                            {
                                Value = (string) item.Attribute("Value"),
                                Default = (bool?) item.Attribute("Default") ?? false,
                                Required = (bool?) item.Attribute("Required") ?? false
                            })
                            .ToList()
                        })
                        .ToList()
                    })
                    .ToList()
            };

            var context = new TemplateContext(model, options)
            {
                CancellationToken = cancellationToken
            };

            return Templates.OpenIddictClientWebIntegrationConfiguration.Render(context);
        }

        static string GenerateHelpers(FluidParser parser, TemplateOptions options, XDocument document, CancellationToken cancellationToken)
        {
            var model = new
            {
                Providers = document.Root.Elements("Provider")
                    .Select(static provider => new
                    {
                        Name = (string) provider.Attribute("Name"),
                        DisplayName = (string?) provider.Attribute("DisplayName") ?? (string) provider.Attribute("Name")
                    })
                    .ToList()
            };

            var context = new TemplateContext(model, options)
            {
                CancellationToken = cancellationToken
            };

            return Templates.OpenIddictClientWebIntegrationHelpers.Render(context);
        }

        static string GenerateSettings(FluidParser parser, TemplateOptions options, XDocument document, CancellationToken cancellationToken)
        {
            var model = new
            {
                Providers = document.Root.Elements("Provider")
                    .Select(static provider => new
                    {
                        Name = (string) provider.Attribute("Name"),
                        DisplayName = (string?) provider.Attribute("DisplayName") ?? (string) provider.Attribute("Name"),

                        Settings = provider.Elements("Setting").Select(static setting => new
                        {
                            PropertyName = (string) setting.Attribute("PropertyName"),

                            Collection = (bool?) setting.Attribute("Collection") ?? false,
                            Obsolete = (bool?) setting.Attribute("Obsolete") ?? false,

                            Description = (string) setting.Attribute("Description") is string description
                                ? $"{char.ToLower(description[0], CultureInfo.GetCultureInfo("en-US"))}{description[1..]}"
                                : null,
                            ClrType = (string) setting.Attribute("Type") switch
                            {
                                "Boolean" => "bool",
                                "EncryptionKey" => (string?) setting.Element("EncryptionAlgorithm")?.Attribute("Value") switch
                                {
                                    "RS256" or "RS384" or "RS512" => "RsaSecurityKey",

                                    _ => "SecurityKey"
                                },

                                "SigningCertificate" => "X509Certificate2",

                                "SigningKey" => (string?) setting.Element("SigningAlgorithm")?.Attribute("Value") switch
                                {
                                    "ES256" or "ES384" or "ES512" => "ECDsaSecurityKey",
                                    "PS256" or "PS384" or "PS512" or "RS256" or "RS384" or "RS512" => "RsaSecurityKey",

                                    _ => "SecurityKey"
                                },

                                "String" => "string",
                                "StringHashSet" => "HashSet<string>",
                                "Uri" => "Uri",

                                string value => value
                            }
                        })
                        .ToList()
                    })
                    .ToList()
            };

            var context = new TemplateContext(model, options)
            {
                CancellationToken = cancellationToken
            };

            return Templates.OpenIddictClientWebIntegrationSettings.Render(context);
        }
    }
}

[FluidTemplates("**/*.liquid", Exclude = ["_*.liquid"])]
internal static partial class Templates;
