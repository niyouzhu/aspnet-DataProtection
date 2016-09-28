// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection.Azure.KeyVault;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Microsoft.AspNetCore.DataProtection
{
    /// <summary>
    /// Contains Azure KeyVault-specific extension methods for modifying a <see cref="IDataProtectionBuilder"/>.
    /// </summary>
    public static class AzureDataProtectionBuilderExtensions
    {
#if NET451
        /// <summary>
        /// Configures the data protection system to protect keys with specified key in Azure KeyVault.
        /// </summary>
        /// <param name="builder">The builder instance to modify.</param>
        /// <param name="keyIdentifier">The Azure KeyVault key identifier used for key encryption.</param>
        /// <param name="clientId">The application client id.</param>
        /// <param name="certificate"></param>
        /// <returns>The value <paramref name="builder"/>.</returns>
        public static IDataProtectionBuilder ProtectKeysWithAzureKeyVault(this IDataProtectionBuilder builder, string keyIdentifier, string clientId, X509Certificate2 certificate)
        {
            if (clientId == null)
            {
                throw new ArgumentNullException(nameof(clientId));
            }
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }
            KeyVaultClient.AuthenticationCallback callback =
                (authority, resource, scope) => GetTokenFromClientCertificate(authority, resource, clientId, certificate);

            return ProtectKeysWithAzureKeyVault(builder, new KeyVaultClient(callback), keyIdentifier);
        }

        private static async Task<string> GetTokenFromClientCertificate(string authority, string resource, string clientId, X509Certificate2 certificate)
        {
            var authContext = new AuthenticationContext(authority);
            var result = await authContext.AcquireTokenAsync(resource, new ClientAssertionCertificate(clientId, certificate));
            return result.AccessToken;
        }
#endif

        /// <summary>
        /// Configures the data protection system to protect keys with specified key in Azure KeyVault.
        /// </summary>
        /// <param name="builder">The builder instance to modify.</param>
        /// <param name="keyIdentifier">The Azure KeyVault key identifier used for key encryption.</param>
        /// <param name="clientId">The application client id.</param>
        /// <param name="clientSecret">The client secret to use for authentication.</param>
        /// <returns>The value <paramref name="builder"/>.</returns>
        public static IDataProtectionBuilder ProtectKeysWithAzureKeyVault(this IDataProtectionBuilder builder, string keyIdentifier, string clientId, string clientSecret)
        {
            if (clientId == null)
            {
                throw new ArgumentNullException(nameof(clientId));
            }
            if (clientSecret == null)
            {
                throw new ArgumentNullException(nameof(clientSecret));
            }
            KeyVaultClient.AuthenticationCallback callback =
                (authority, resource, scope) => GetTokenFromClientSecret(authority, resource, clientId, clientSecret);

            return ProtectKeysWithAzureKeyVault(builder, new KeyVaultClient(callback), keyIdentifier);
        }

        private static async Task<string> GetTokenFromClientSecret(string authority, string resource, string clientId, string clientSecret)
        {
            var authContext = new AuthenticationContext(authority);
            var clientCred = new ClientCredential(clientId, clientSecret);
            var result = await authContext.AcquireTokenAsync(resource, clientCred);
            return result.AccessToken;
        }

        /// <summary>
        /// Configures the data protection system to protect keys with specified key in Azure KeyVault.
        /// </summary>
        /// <param name="builder">The builder instance to modify.</param>
        /// <param name="keyIdentifier">The Azure KeyVault key identifier used for key encryption.</param>
        /// <param name="client">The <see cref="KeyVaultClient"/> to use for KeyVault access.</param>
        /// <returns>The value <paramref name="builder"/>.</returns>
        public static IDataProtectionBuilder ProtectKeysWithAzureKeyVault(this IDataProtectionBuilder builder, KeyVaultClient client, string keyIdentifier)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }
            if (client == null)
            {
                throw new ArgumentNullException(nameof(client));
            }
            if (keyIdentifier == null)
            {
                throw new ArgumentNullException(nameof(keyIdentifier));
            }
            var vaultClientWrapper = new KeyVaultClientWrapper(client);

            builder.Services.AddSingleton<IKeyVaultWrappingClient>(vaultClientWrapper);
            builder.Services.AddSingleton<IXmlEncryptor>(services => new AzureKeyVaultXmlEncryptor(vaultClientWrapper, keyIdentifier));
            return builder;
        }
    }
}