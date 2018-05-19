/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using NHibernate.Mapping.ByCode;
using NHibernate.Mapping.ByCode.Conformist;
using OpenIddict.NHibernate.Models;

namespace OpenIddict.NHibernate
{
    /// <summary>
    /// Defines a relational mapping for the Application entity.
    /// </summary>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TKey">The type of the Key entity.</typeparam>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictApplicationMapping<TApplication, TAuthorization, TToken, TKey> : ClassMapping<TApplication>
        where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>
        where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>
        where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>
        where TKey : IEquatable<TKey>
    {
        public OpenIddictApplicationMapping()
        {
            Id(application => application.Id, map =>
            {
                map.Generator(Generators.Identity);
            });

            Version(application => application.Version, map =>
            {
                map.Insert(true);
            });

            Property(application => application.ClientId, map =>
            {
                map.NotNullable(true);
                map.Unique(true);
            });

            Property(application => application.ClientSecret);

            Property(application => application.ConsentType);

            Property(application => application.DisplayName);

            Property(application => application.Permissions, map =>
            {
                map.Length(10000);
            });

            Property(application => application.PostLogoutRedirectUris, map =>
            {
                map.Length(10000);
            });

            Property(application => application.Properties, map =>
            {
                map.Length(10000);
            });

            Property(application => application.RedirectUris, map =>
            {
                map.Length(10000);
            });

            Property(application => application.Type, map =>
            {
                map.NotNullable(true);
            });

            Bag(application => application.Authorizations,
                map =>
                {
                    map.Key(key => key.Column("ApplicationId"));
                },
                map =>
                {
                    map.OneToMany();
                });

            Bag(application => application.Tokens,
                map =>
                {
                    map.Key(key => key.Column("ApplicationId"));
                },
                map =>
                {
                    map.OneToMany();
                });

            Table("OpenIddictApplications");
        }
    }
}
