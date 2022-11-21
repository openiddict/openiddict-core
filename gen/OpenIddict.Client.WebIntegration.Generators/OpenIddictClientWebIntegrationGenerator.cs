using System.Globalization;
using System.Text;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Scriban;

namespace OpenIddict.Client.WebIntegration.Generators
{
    [Generator]
    public sealed class OpenIddictClientWebIntegrationGenerator : ISourceGenerator
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
                "OpenIddictClientWebIntegrationConfiguration.generated.cs",
                SourceText.From(GenerateConfigurationClasses(document), Encoding.UTF8));

            context.AddSource(
                "OpenIddictClientWebIntegrationConstants.generated.cs",
                SourceText.From(GenerateConstants(document), Encoding.UTF8));

            context.AddSource(
                "OpenIddictClientWebIntegrationHelpers.generated.cs",
                SourceText.From(GenerateHelpers(document), Encoding.UTF8));

            context.AddSource(
                "OpenIddictClientWebIntegrationOptions.generated.cs",
                SourceText.From(GenerateOptions(document), Encoding.UTF8));

            static string GenerateBuilderMethods(XDocument document)
            {
                var template = Template.Parse(@"#nullable enable

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Client;
using OpenIddict.Client.WebIntegration;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace Microsoft.Extensions.DependencyInjection;

public sealed partial class OpenIddictClientWebIntegrationBuilder
{
    {{~ for provider in providers ~}}
    /// <summary>
    /// Enables the {{ provider.name }} integration and registers the associated services in the DI container.
    {{~ if provider.documentation ~}}
    /// For more information, read <see href=""{{ provider.documentation }}"">the documentation</see>.
    /// </summary>
    {{~ end ~}}
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
    public OpenIddictClientWebIntegrationBuilder.{{ provider.name }} Use{{ provider.name }}()
    {
        // Note: TryAddEnumerable() is used here to ensure the initializers are registered only once.
        Services.TryAddEnumerable(new[]
        {
            ServiceDescriptor.Singleton<
                IConfigureOptions<OpenIddictClientOptions>, OpenIddictClientWebIntegrationConfiguration.{{ provider.name }}>(),
            ServiceDescriptor.Singleton<
                IPostConfigureOptions<OpenIddictClientWebIntegrationOptions.{{ provider.name }}>, OpenIddictClientWebIntegrationConfiguration.{{ provider.name }}>()
        });

        return new OpenIddictClientWebIntegrationBuilder.{{ provider.name }}(Services);
    }

    /// <summary>
    /// Enables the {{ provider.name }} integration and registers the associated services in the DI container.
    {{~ if provider.documentation ~}}
    /// For more information, read <see href=""{{ provider.documentation }}"">the documentation</see>.
    /// </summary>
    {{~ end ~}}
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <param name=""configuration"">The delegate used to configure the OpenIddict/{{ provider.name }} options.</param>
    /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder""/> instance.</returns>
    public OpenIddictClientWebIntegrationBuilder Use{{ provider.name }}(Action<OpenIddictClientWebIntegrationBuilder.{{ provider.name }}> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        configuration(Use{{ provider.name }}());

        return this;
    }
    {{~ end ~}}

    {{~ for provider in providers ~}}
    /// <summary>
    /// Exposes the necessary methods required to configure the {{ provider.name }} integration.
    /// </summary>
    public sealed partial class {{ provider.name }}
    {
        /// <summary>
        /// Initializes a new instance of <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/>.
        /// </summary>
        /// <param name=""services"">The services collection.</param>
        public {{ provider.name }}(IServiceCollection services)
            => Services = services ?? throw new ArgumentNullException(nameof(services));

        /// <summary>
        /// Gets the services collection.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IServiceCollection Services { get; }

        /// <summary>
        /// Amends the default OpenIddict client {{ provider.name }} configuration.
        /// </summary>
        /// <param name=""configuration"">The delegate used to configure the OpenIddict options.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} Configure(Action<OpenIddictClientWebIntegrationOptions.{{ provider.name }}> configuration)
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            Services.Configure(configuration);

            return this;
        }

        /// <summary>
        /// Sets the client identifier.
        /// </summary>
        /// <param name=""identifier"">The client identifier.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetClientId(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(identifier));
            }

            return Configure(options => options.ClientId = identifier);
        }

        /// <summary>
        /// Sets the client secret, if applicable.
        /// </summary>
        /// <param name=""secret"">The client secret.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetClientSecret(string secret)
        {
            if (string.IsNullOrEmpty(secret))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0125), nameof(secret));
            }

            return Configure(options => options.ClientSecret = secret);
        }

        /// <summary>
        /// Sets the redirection URI, if applicable.
        /// </summary>
        /// <param name=""address"">The redirection URI.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetRedirectUri(Uri address)
        {
            if (address is null)
            {
                throw new ArgumentNullException(nameof(address));
            }

            if (!address.IsAbsoluteUri || !address.IsWellFormedOriginalString())
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(address));
            }

            return Configure(options => options.RedirectUri = address);
        }

        /// <summary>
        /// Sets the redirection URI, if applicable.
        /// </summary>
        /// <param name=""address"">The redirection URI.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetRedirectUri([StringSyntax(StringSyntaxAttribute.Uri)] string address)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0143), nameof(address));
            }

            if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? uri))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(address));
            }

            return SetRedirectUri(uri);
        }

        /// <summary>
        /// Adds one or more scopes to the list of requested scopes, if applicable.
        /// </summary>
        /// <param name=""scopes"">The scopes.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} AddScopes(params string[] scopes)
        {
            if (scopes is null)
            {
                throw new ArgumentNullException(nameof(scopes));
            }

            return Configure(options => options.Scopes.UnionWith(scopes));
        }

        {{~ for environment in provider.environments ~}}
        /// <summary>
        /// Configures the provider to use the ""{{ environment.name }}"" environment.
        /// </summary>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} Use{{ environment.name }}Environment()
            => Configure(options => options.Environment = OpenIddictClientWebIntegrationConstants.{{ provider.name }}.Environments.{{ environment.name }});
        {{~ end ~}}

        {{~ for setting in provider.settings ~}}
        {{~ if setting.collection ~}}
        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""{{ setting.parameter_name }}"">{{ setting.description | string.capitalize }}.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} Add{{ setting.property_name }}(params {{ setting.clr_type }}[] {{ setting.parameter_name }})
        {
            if ({{ setting.parameter_name }} is null)
            {
                throw new ArgumentNullException(nameof({{ setting.parameter_name }}));
            }

            return Configure(options => options.{{ setting.property_name }}.UnionWith({{ setting.parameter_name }}));
        }
        {{~ else if setting.clr_type == 'Uri' ~}}
        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""{{ setting.parameter_name }}"">{{ setting.description | string.capitalize }}.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} Set{{ setting.property_name }}(Uri {{ setting.parameter_name }})
        {
            if ({{ setting.parameter_name }} is null)
            {
                throw new ArgumentNullException(nameof({{ setting.parameter_name }}));
            }

            if (!{{ setting.parameter_name }}.IsAbsoluteUri || !{{ setting.parameter_name }}.IsWellFormedOriginalString())
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof({{ setting.parameter_name }}));
            }

            return Configure(options => options.{{ setting.property_name }} = {{ setting.parameter_name }});
        }

        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""{{ setting.parameter_name }}"">{{ setting.description | string.capitalize }}.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} Set{{ setting.property_name }}(string {{ setting.parameter_name }})
        {
            if (string.IsNullOrEmpty({{ setting.parameter_name }}))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0143), nameof({{ setting.parameter_name }}));
            }

            if (!Uri.TryCreate({{ setting.parameter_name }}, UriKind.Absolute, out Uri? uri))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof({{ setting.parameter_name }}));
            }

            return Set{{ setting.property_name }}(uri);
        }
        {{~ else ~}}
        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""{{ setting.parameter_name }}"">{{ setting.description | string.capitalize }}.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} Set{{ setting.property_name }}({{ setting.clr_type }} {{ setting.parameter_name }})
        {
            if ({{ setting.parameter_name }} is null)
            {
                throw new ArgumentNullException(nameof({{ setting.parameter_name }}));
            }

            return Configure(options => options.{{ setting.property_name }} = {{ setting.parameter_name }});
        }
        {{~ end ~}}

        {{~ end ~}}

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(object? obj) => base.Equals(obj);

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => base.GetHashCode();

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string? ToString() => base.ToString();
    }
    {{~ end ~}}
}
");
                return template.Render(new
                {
                    Providers = document.Root.Elements("Provider")
                        .Select(provider => new
                        {
                            Name = (string) provider.Attribute("Name"),
                            Documentation = (string?) provider.Attribute("Documentation"),

                            Environments = provider.Elements("Environment").Select(environment => new
                            {
                                Name = (string?) environment.Attribute("Name") ?? "Production"
                            })
                            .ToList(),

                            Settings = provider.Elements("Setting").Select(setting => new
                            {
                                PropertyName = (string) setting.Attribute("PropertyName"),
                                ParameterName = (string) setting.Attribute("ParameterName"),

                                Collection = (bool?) setting.Attribute("Collection") ?? false,
                                Description = (string) setting.Attribute("Description") is string description ?
                                    char.ToLower(description[0], CultureInfo.GetCultureInfo("en-US")) + description[1..] : null,
                                ClrType = (string) setting.Attribute("Type") switch
                                {
                                    "EncryptionKey" when (string) setting.Element("EncryptionAlgorithm").Attribute("Value")
                                        is "RS256" or "RS384" or "RS512" => "RsaSecurityKey",

                                    "SigningKey" when (string) setting.Element("SigningAlgorithm").Attribute("Value")
                                        is "ES256" or "ES384" or "ES512" => "ECDsaSecurityKey",

                                    "SigningKey" when (string) setting.Element("SigningAlgorithm").Attribute("Value")
                                        is "PS256" or "PS384" or "PS512" or
                                           "RS256" or "RS384" or "RS512" => "RsaSecurityKey",

                                    "String" => "string",
                                    "StringHashSet" => "HashSet<string>",
                                    "Uri" => "Uri",

                                    string value => value
                                }
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
    {{~ for provider in providers ~}}
    public static class {{ provider.name }}
    {
        public static class Environments
        {
            {{~ for environment in provider.environments ~}}
            public const string {{ environment.name }} = ""{{ environment.name }}"";
            {{~ end ~}}
        }
    }
    {{~ end ~}}

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
                        .Select(provider => new
                        {
                            Name = (string) provider.Attribute("Name"),

                            Environments = provider.Elements("Environment").Select(environment => new
                            {
                                Name = (string?) environment.Attribute("Name") ?? "Production"
                            })
                            .ToList(),
                        })
                        .ToList()
                });
            }

            static string GenerateConfigurationClasses(XDocument document)
            {
                var template = Template.Parse(@"#nullable enable

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Client;
using SmartFormat;
using SmartFormat.Core.Settings;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public sealed partial class OpenIddictClientWebIntegrationConfiguration
{
    {{~ for provider in providers ~}}
    /// <summary>
    /// Contains the methods required to register the {{ provider.name }} integration in the OpenIddict client options.
    /// </summary>
    public sealed class {{ provider.name }} : IConfigureOptions<OpenIddictClientOptions>,
                                              IPostConfigureOptions<OpenIddictClientWebIntegrationOptions.{{ provider.name }}>
    {
        private readonly IServiceProvider _provider;

        /// <summary>
        /// Creates a new instance of the <see cref=""OpenIddictClientWebIntegrationConfiguration.{{ provider.name }}"" /> class.
        /// </summary>
        /// <param name=""provider"">The service provider.</param>
        /// <exception cref=""ArgumentException""><paramref name=""provider""/> is null.</exception>
        public {{ provider.name }}(IServiceProvider provider)
            => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

        /// <summary>
        /// Ensures the {{ provider.name }} configuration is in a consistent and valid state.
        /// </summary>
        /// <param name=""name"">The name of the options instance to configure, if applicable.</param>
        /// <param name=""options"">The options instance to initialize.</param>
        public void PostConfigure(string? name, OpenIddictClientWebIntegrationOptions.{{ provider.name }} options)
        {
            {{~ for setting in provider.settings ~}}
            {{~ if setting.default_value && setting.type == 'String' ~}} 
            if (string.IsNullOrEmpty(options.{{ setting.property_name }}))
            {
                options.{{ setting.property_name }} = ""{{ setting.default_value }}"";
            }
            {{~ end ~}}

            {{~ if setting.collection ~}}
            if (options.{{ setting.property_name }}.Count is 0)
            {
                {{~ for item in setting.items ~}}
                {{~ if item.default && !item.required ~}}
                options.{{ setting.property_name }}.Add(""{{ item.value }}"");
                {{~ end ~}}
                {{~ end ~}}
            }
            {{~ end ~}}

            {{~ for item in setting.items ~}}
            {{~ if item.required ~}}
            options.{{ setting.property_name }}.Add(""{{ item.value }}"");
            {{~ end ~}}
            {{~ end ~}}
            {{~ end ~}}

            {{~ for environment in provider.environments ~}}
            if (options.Environment is OpenIddictClientWebIntegrationConstants.{{ provider.name }}.Environments.{{ environment.name }})
            {
                if (options.Scopes.Count is 0)
                {
                    {{~ for scope in environment.scopes ~}}
                    {{~ if scope.default && !scope.required ~}}
                    options.Scopes.Add(""{{ scope.name }}"");
                    {{~ end ~}}
                    {{~ end ~}}
                }

                {{~ for scope in environment.scopes ~}}
                {{~ if scope.required ~}}
                options.Scopes.Add(""{{ scope.name }}"");
                {{~ end ~}}
                {{~ end ~}}
            }
            {{~ end ~}}

            if (string.IsNullOrEmpty(options.ClientId))
            {
                throw new InvalidOperationException(SR.FormatID0332(nameof(options.ClientId), Providers.{{ provider.name }}));
            }

            {{~ for setting in provider.settings ~}}
            {{~ if setting.required ~}}
            {{~ if setting.type == 'String' ~}}
            if (string.IsNullOrEmpty(options.{{ setting.property_name }}))
            {{~ else ~}}
            if (options.{{ setting.property_name }} is null)
            {{~ end ~}}
            {
                throw new InvalidOperationException(SR.FormatID0332(nameof(options.{{ setting.property_name }}), Providers.{{ provider.name }}));
            }
            {{~ end ~}}

            {{~ if setting.type == 'Uri' ~}}
            if (!options.{{ setting.property_name }}.IsAbsoluteUri || !options.{{ setting.property_name }}.IsWellFormedOriginalString())
            {
                throw new InvalidOperationException(SR.FormatID0350(nameof(options.{{ setting.property_name }}), Providers.{{ provider.name }}));
            }
            {{~ end ~}}
            {{~ end ~}}
        }

        /// <summary>
        /// Registers the {{ provider.name }} integration in the OpenIddict client options.
        /// </summary>
        /// <param name=""options"">The options instance to initialize.</param>
        public void Configure(OpenIddictClientOptions options)
        {
            // Resolve the provider options from the service provider and create a registration based on the specified settings.
            var settings = _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientWebIntegrationOptions.{{ provider.name }}>>().CurrentValue;

            var formatter = Smart.CreateDefaultSmartFormat(new SmartSettings
            {
                CaseSensitivity = CaseSensitivityType.CaseInsensitive
            });

            var registration = new OpenIddictClientRegistration
            {
                ProviderName = Providers.{{ provider.name }},
                ProviderOptions = settings,

                Issuer = settings.Environment switch
                {
                    {{~ for environment in provider.environments ~}}
                    OpenIddictClientWebIntegrationConstants.{{ provider.name }}.Environments.{{ environment.name }}
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
                    OpenIddictClientWebIntegrationConstants.{{ provider.name }}.Environments.{{ environment.name }} => new OpenIddictConfiguration
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
                    OpenIddictClientWebIntegrationConstants.{{ provider.name }}.Environments.{{ environment.name }} => null,
                    {{~ end ~}}
                    {{~ end ~}}

                    _ => throw new InvalidOperationException(SR.FormatID0194(nameof(settings.Environment)))
                },

                EncryptionCredentials =
                {
                    {{~ for setting in provider.settings ~}}
                    {{~ if setting.type == 'EncryptionKey' ~}}
                    new EncryptingCredentials(settings.{{ setting.property_name }}, ""{{ setting.encryption_algorithm }}"", SecurityAlgorithms.Aes256CbcHmacSha512),
                    {{~ end ~}}
                    {{~ end ~}}
                },

                SigningCredentials =
                {
                    {{~ for setting in provider.settings ~}}
                    {{~ if setting.type == 'SigningKey' ~}}
                    new SigningCredentials(settings.{{ setting.property_name }}, ""{{ setting.signing_algorithm }}""),
                    {{~ end ~}}
                    {{~ end ~}}
                }
            };

            registration.Scopes.UnionWith(settings.Scopes);

            options.Registrations.Add(registration);
        }
    }
    {{~ end ~}}
}
");
                return template.Render(new
                {
                    Providers = document.Root.Elements("Provider")
                        .Select(provider => new
                        {
                            Name = (string) provider.Attribute("Name"),

                            Environments = provider.Elements("Environment").Select(environment => new
                            {
                                Name = (string?) environment.Attribute("Name") ?? "Production",
                                Issuer = (string) environment.Attribute("Issuer"),
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
                                },

                                Scopes = environment.Elements("Scope").Select(setting => new
                                {
                                    Name = (string) setting.Attribute("Name"),
                                    Default = (bool?) setting.Attribute("Default") ?? false,
                                    Required = (bool?) setting.Attribute("Required") ?? false
                                })
                            })
                            .ToList(),

                            Settings = provider.Elements("Setting").Select(setting => new
                            {
                                PropertyName = (string) setting.Attribute("PropertyName"),

                                Type = (string) setting.Attribute("Type"),
                                Required = (bool?) setting.Attribute("Required") ?? false,
                                Collection = (bool?) setting.Attribute("Collection") ?? false,

                                EncryptionAlgorithm = (string?) setting.Element("EncryptionAlgorithm")?.Attribute("Value"),
                                SigningAlgorithm = (string?) setting.Element("SigningAlgorithm")?.Attribute("Value"),

                                DefaultValue = (string?) setting.Attribute("DefaultValue"),

                                Items = setting.Elements("Item").Select(item => new
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
                });
            }

            static string GenerateHelpers(XDocument document)
            {
                var template = Template.Parse(@"#nullable enable

using Microsoft.IdentityModel.Tokens;
using OpenIddict.Client;
using OpenIddict.Client.WebIntegration;
using SmartFormat;
using SmartFormat.Core.Settings;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHelpers
{
    {{~ for provider in providers ~}}
    /// <summary>
    /// Resolves the {{ provider.name }} provider options from the specified registration.
    /// </summary>
    /// <param name=""registration"">The client registration.</param>
    /// <returns>The {{ provider.name }} provider options.</returns>
    /// <exception cref=""InvalidOperationException"">The provider options cannot be resolved.</exception>
    public static OpenIddictClientWebIntegrationOptions.{{ provider.name }} Get{{ provider.name }}Options(this OpenIddictClientRegistration registration)
        => registration.ProviderOptions is OpenIddictClientWebIntegrationOptions.{{ provider.name }} options ? options :
            throw new InvalidOperationException(SR.FormatID0333(Providers.{{ provider.name }}));

    {{~ end ~}}
}
");
                return template.Render(new
                {
                    Providers = document.Root.Elements("Provider")
                        .Select(provider => new { Name = (string) provider.Attribute("Name") })
                        .ToList()
                });
            }

            static string GenerateOptions(XDocument document)
            {
                var template = Template.Parse(@"#nullable enable

using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client.WebIntegration;

public sealed partial class OpenIddictClientWebIntegrationOptions
{
    {{~ for provider in providers ~}}
    /// <summary>
    /// Provides various options needed to configure the {{ provider.name }} integration.
    /// </summary>
    public sealed class {{ provider.name }}
    {
        /// <summary>
        /// Gets or sets the client identifier.
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client secret, if applicable.
        /// </summary>
        public string? ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the redirection URL.
        /// </summary>
        public Uri? RedirectUri { get; set; }

        /// <summary>
        /// Gets the scopes requested to the authorization server.
        /// </summary>
        public HashSet<string> Scopes { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the environment that determines the endpoints to use (by default, ""Production"").
        /// </summary>
        public string? Environment { get; set; } = OpenIddictClientWebIntegrationConstants.{{ provider.name }}.Environments.Production;

        {{~ for setting in provider.settings ~}}
        /// <summary>
        /// Gets or sets {{ setting.description }}.
        /// </summary>
        {{~ if setting.collection ~}}
        public HashSet<{{ setting.clr_type }}> {{ setting.property_name }} { get; } = new();
        {{~ else ~}}
        public {{ setting.clr_type }}? {{ setting.property_name }} { get; set; }
        {{~ end ~}}

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
                            Name = (string) provider.Attribute("Name"),

                            Settings = provider.Elements("Setting").Select(setting => new
                            {
                                PropertyName = (string) setting.Attribute("PropertyName"),

                                Collection = (bool?) setting.Attribute("Collection") ?? false,
                                Description = (string) setting.Attribute("Description") is string description ?
                                    char.ToLower(description[0], CultureInfo.GetCultureInfo("en-US")) + description[1..] : null,
                                ClrType = (string) setting.Attribute("Type") switch
                                {
                                    "EncryptionKey" when (string) setting.Element("EncryptionAlgorithm").Attribute("Value")
                                        is "RS256" or "RS384" or "RS512" => "RsaSecurityKey",

                                    "SigningKey" when (string) setting.Element("SigningAlgorithm").Attribute("Value")
                                        is "ES256" or "ES384" or "ES512" => "ECDsaSecurityKey",

                                    "SigningKey" when (string) setting.Element("SigningAlgorithm").Attribute("Value")
                                        is "PS256" or "PS384" or "PS512" or
                                           "RS256" or "RS384" or "RS512" => "RsaSecurityKey",

                                    "String" => "string",
                                    "StringHashSet" => "HashSet<string>",
                                    "Uri" => "Uri",

                                    string value => value
                                }
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
