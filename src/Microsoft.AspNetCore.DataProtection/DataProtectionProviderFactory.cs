// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;
using Microsoft.AspNetCore.Cryptography.Cng;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.Cng;
using Microsoft.AspNetCore.DataProtection.Internal;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.KeyManagement.Internal;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;

namespace Microsoft.AspNetCore.DataProtection
{
    /// <summary>
    /// Contains static factory methods for creating <see cref="IDataProtectionProvider"/> instances.
    /// </summary>
    internal static class DataProtectionProviderFactory
    {
        /// <summary>
        /// Creates an <see cref="IDataProtectionProvider"/> given an <see cref="IServiceProvider"/>.
        /// </summary>
        /// <param name="options">The global options to use when creating the provider.</param>
        /// <param name="services">Provides mandatory services for use by the provider.</param>
        /// <returns>An <see cref="IDataProtectionProvider"/>.</returns>
        public static IDataProtectionProvider GetProviderFromServices(DataProtectionOptions options, IServiceProvider services)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            return GetProviderFromServices(options, services, mustCreateImmediately: false);
        }

        internal static IDataProtectionProvider GetProviderFromServices(DataProtectionOptions options, IServiceProvider services, bool mustCreateImmediately)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            IDataProtectionProvider dataProtectionProvider = null;

            // If we're being asked to create the provider immediately, then it means that
            // we're already in a call to GetService, and we're responsible for supplying
            // the default implementation ourselves. We can't call GetService again or
            // else we risk stack diving.
            if (!mustCreateImmediately)
            {
                dataProtectionProvider = services.GetService<IDataProtectionProvider>();
            }

            // If all else fails, create a keyring manually based on the other registered services.
            if (dataProtectionProvider == null)
            {
                var keyRingProvider = new KeyRingProvider(
                    keyManager: services.GetRequiredService<IKeyManager>(),
                    keyManagementOptions: services.GetService<IOptions<KeyManagementOptions>>()?.Value, // might be null
                    services: services);
                dataProtectionProvider = new KeyRingBasedDataProtectionProvider(keyRingProvider, services);
            }

            // Finally, link the provider to the supplied discriminator
            if (!String.IsNullOrEmpty(options.ApplicationDiscriminator))
            {
                dataProtectionProvider = dataProtectionProvider.CreateProtector(options.ApplicationDiscriminator);
            }

            return dataProtectionProvider;
        }

        public static IDataProtectionProvider Create(DataProtectionOptions dpOptions, KeyManagementOptions kmOptions)
        {
            if (dpOptions == null)
            {
                throw new ArgumentNullException(nameof(dpOptions));
            }

            RegistryPolicyContext registryPolicyContext = null;

            if (OSVersionUtil.IsWindows())
            {
                registryPolicyContext = RegistryPolicyResolver.ResolveDefaultPolicy(GetActivator(), GetLoggerFactory());
                if (kmOptions == null && registryPolicyContext.DefaultKeyLifetime.HasValue)
                {
                    kmOptions = new KeyManagementOptions
                    {
                        NewKeyLifetime = TimeSpan.FromDays(registryPolicyContext.DefaultKeyLifetime.Value)
                    };
                }
            }


            var keyRingProvider = GetKeyRingProvider(kmOptions, registryPolicyContext);
            var loggerFactory = GetLoggerFactory();

            IDataProtectionProvider dataProtectionProvider = null;
            dataProtectionProvider = new KeyRingBasedDataProtectionProvider(keyRingProvider, loggerFactory);

            // Link the provider to the supplied discriminator
            if (!String.IsNullOrEmpty(dpOptions.ApplicationDiscriminator))
            {
                dataProtectionProvider = dataProtectionProvider.CreateProtector(dpOptions.ApplicationDiscriminator);
            }

            return dataProtectionProvider;
        }

        //private static string GetApplicationUniqueIdentifier(this IServiceProvider services)
        //{
        //    string discriminator = null;
        //    if (services != null)
        //    {
        //        discriminator = services.GetService<IApplicationDiscriminator>()?.Discriminator;
        //        if (discriminator == null)
        //        {
        //            discriminator = services.GetService<IHostingEnvironment>()?.ContentRootPath;
        //        }
        //    }

        //    // Remove whitespace and homogenize empty -> null
        //    discriminator = discriminator?.Trim();
        //    return (string.IsNullOrEmpty(discriminator)) ? null : discriminator;
        //}

        private static IKeyRingProvider GetKeyRingProvider(KeyManagementOptions kmOptions, RegistryPolicyContext registryPolicyContext)
        {
            var keyRingProvider = new KeyRingProvider(
                    keyManager: GetKeyManager(registryPolicyContext),
                    kmOptions: kmOptions,
                    cacheableKeyRingProvider: null,
                    defaultKeyResolver: GetDefaultKeyResolver(kmOptions),
                    loggerFactory: GetLoggerFactory());

            return keyRingProvider;
        }

        private static IDefaultKeyResolver GetDefaultKeyResolver(KeyManagementOptions kmOptions)
        {
            return new DefaultKeyResolver(kmOptions.KeyPropagationWindow, kmOptions.MaxServerClockSkew, GetLoggerFactory());
        }

        private static IKeyManager GetKeyManager(RegistryPolicyContext registryPolicyContext)
        {
            var keyRepositoryEncryptorPair = GetKeyRepositoryEncryptorPair();
            return new XmlKeyManager(
                repository: keyRepositoryEncryptorPair.Key,
                encryptor: keyRepositoryEncryptorPair.Value,
                authenticatedEncryptorConfiguration: GetAuthenticatedEncryptorConfiguration(registryPolicyContext),
                keyEscrowSink: GetKeyEscrowSink(registryPolicyContext),
                internalKeyManager: null,
                activator: GetActivator(),
                loggerFactory: GetLoggerFactory());
        }

        private static IAuthenticatedEncryptorConfiguration GetAuthenticatedEncryptorConfiguration(RegistryPolicyContext registryPolicyContext)
        {
            if (registryPolicyContext != null)
            {
                return registryPolicyContext.EncryptorConfiguration;
            }

            return new AuthenticatedEncryptorConfiguration(new AuthenticatedEncryptionSettings(), GetLoggerFactory());
        }

        private static IKeyEscrowSink GetKeyEscrowSink(RegistryPolicyContext registryPolicyContext)
        {
            var escrowSinks = registryPolicyContext?.KeyEscrowSinks.ToList();

            return (escrowSinks != null && escrowSinks.Count > 0) ? new AggregateKeyEscrowSink(escrowSinks) : null;
        }

        private static IActivator GetActivator()
        {
            return SimpleActivator.DefaultWithoutServices;
        }

        private static ILoggerFactory GetLoggerFactory()
        {
            return NullLoggerFactory.Instance;
        }

        private static KeyValuePair<IXmlRepository, IXmlEncryptor> GetKeyRepositoryEncryptorPair()
        {
            IXmlRepository repository = null;
            IXmlEncryptor encryptor = null;
            var loggerFactory = GetLoggerFactory();

            // If we're running in Azure Web Sites, the key repository goes in the %HOME% directory.
            var azureWebSitesKeysFolder = FileSystemXmlRepository.GetKeyStorageDirectoryForAzureWebSites();
            if (azureWebSitesKeysFolder != null)
            {
                //log?.UsingAzureAsKeyRepository(azureWebSitesKeysFolder.FullName);

                // Cloud DPAPI isn't yet available, so we don't encrypt keys at rest.
                // This isn't all that different than what Azure Web Sites does today, and we can always add this later.
                repository = new FileSystemXmlRepository(azureWebSitesKeysFolder, loggerFactory);
            }
            else
            {
                // If the user profile is available, store keys in the user profile directory.
                var localAppDataKeysFolder = FileSystemXmlRepository.DefaultKeyStorageDirectory;
                if (localAppDataKeysFolder != null)
                {
                    if (OSVersionUtil.IsWindows())
                    {
                        // If the user profile is available, we can protect using DPAPI.
                        // Probe to see if protecting to local user is available, and use it as the default if so.
                        encryptor = new DpapiXmlEncryptor(
                            protectToLocalMachine: !DpapiSecretSerializerHelper.CanProtectToCurrentUserAccount(),
                            loggerFactory: loggerFactory);
                    }
                    repository = new FileSystemXmlRepository(localAppDataKeysFolder, loggerFactory);

                    if (encryptor != null)
                    {
                        //log?.UsingProfileAsKeyRepositoryWithDPAPI(localAppDataKeysFolder.FullName);
                    }
                    else
                    {
                        //log?.UsingProfileAsKeyRepository(localAppDataKeysFolder.FullName);
                    }
                }
                else
                {
                    // Use profile isn't available - can we use the HKLM registry?
                    RegistryKey regKeyStorageKey = null;
                    if (OSVersionUtil.IsWindows())
                    {
                        regKeyStorageKey = RegistryXmlRepository.DefaultRegistryKey;
                    }
                    if (regKeyStorageKey != null)
                    {
                        // If the user profile isn't available, we can protect using DPAPI (to machine).
                        encryptor = new DpapiXmlEncryptor(protectToLocalMachine: true, loggerFactory: loggerFactory);
                        repository = new RegistryXmlRepository(regKeyStorageKey, loggerFactory);

                        //log?.UsingRegistryAsKeyRepositoryWithDPAPI(regKeyStorageKey.Name);
                    }
                    else
                    {
                        // Final fallback - use an ephemeral repository since we don't know where else to go.
                        // This can only be used for development scenarios.
                        repository = new EphemeralXmlRepository(loggerFactory);

                        //log?.UsingEphemeralKeyRepository();
                    }
                }
            }

            return new KeyValuePair<IXmlRepository, IXmlEncryptor>(repository, encryptor);
        }

        private sealed class AggregateKeyEscrowSink : IKeyEscrowSink
        {
            private readonly List<IKeyEscrowSink> _sinks;

            public AggregateKeyEscrowSink(List<IKeyEscrowSink> sinks)
            {
                _sinks = sinks;
            }

            public void Store(Guid keyId, XElement element)
            {
                foreach (var sink in _sinks)
                {
                    sink.Store(keyId, element);
                }
            }
        }
    }
}
