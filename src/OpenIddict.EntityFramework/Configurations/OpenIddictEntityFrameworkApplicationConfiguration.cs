/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity.Infrastructure.Annotations;
using System.Data.Entity.ModelConfiguration;
using OpenIddict.EntityFramework.Models;

namespace OpenIddict.EntityFramework;

/// <summary>
/// Defines a relational mapping for the Application entity.
/// </summary>
/// <typeparam name="TApplication">The type of the Application entity.</typeparam>
/// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
/// <typeparam name="TToken">The type of the Token entity.</typeparam>
/// <typeparam name="TKey">The type of the Key entity.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictEntityFrameworkApplicationConfiguration<TApplication, TAuthorization, TToken, TKey> : EntityTypeConfiguration<TApplication>
    where TApplication : OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TToken>
    where TAuthorization : OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TToken>
    where TToken : OpenIddictEntityFrameworkToken<TKey, TApplication, TAuthorization>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkApplicationConfiguration()
    {
        // Warning: optional foreign keys MUST NOT be added as CLR properties because
        // Entity Framework would throw an exception due to the TKey generic parameter
        // being non-nullable when using value types like short, int, long or Guid.

        HasKey(application => application.Id);

        Property(application => application.ClientId)
            .HasMaxLength(100)
            .HasColumnAnnotation(IndexAnnotation.AnnotationName, new IndexAnnotation(new IndexAttribute
            {
                IsUnique = true
            }));

        Property(application => application.ConcurrencyToken)
            .HasMaxLength(50)
            .IsConcurrencyToken();

        Property(application => application.ConsentType)
            .HasMaxLength(50);

        Property(application => application.Type)
            .HasMaxLength(50);

        HasMany(application => application.Authorizations)
            .WithOptional(authorization => authorization.Application!)
            .Map(association =>
            {
                association.MapKey(nameof(OpenIddictEntityFrameworkAuthorization.Application) +
                                   nameof(OpenIddictEntityFrameworkApplication.Id));
            });

        HasMany(application => application.Tokens)
            .WithOptional(token => token.Application!)
            .Map(association =>
            {
                association.MapKey(nameof(OpenIddictEntityFrameworkToken.Application) +
                                   nameof(OpenIddictEntityFrameworkApplication.Id));
            });

        ToTable("OpenIddictApplications");
    }
}
