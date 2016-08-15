// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
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
        public static IDataProtectionProvider Create(DataProtectionOptions dpOptions, KeyManagementOptions kmOptions, ILoggerFactory loggerFactory, IActivator activator)
        {
            if (dpOptions == null)
            {
                throw new ArgumentNullException(nameof(dpOptions));
            }

            if (kmOptions == null)
            {
                throw new ArgumentNullException(nameof(kmOptions));
            }

            loggerFactory = loggerFactory ?? GetDefaultLoggerFactory();
            activator = activator ?? GetDefaultActivator();
            RegistryPolicyContext registryPolicyContext = null;
            if (OSVersionUtil.IsWindows())
            {
                registryPolicyContext = RegistryPolicyResolver.ResolveDefaultPolicy(activator, loggerFactory);
            }

            PopulateDefaultOptions(kmOptions, registryPolicyContext, loggerFactory);

            var keyRingProvider = GetKeyRingProvider(kmOptions, loggerFactory, activator);

            return Create(dpOptions, keyRingProvider, loggerFactory);
        }

        internal static IDataProtectionProvider Create(
            DataProtectionOptions dpOptions,
            IKeyRingProvider keyRingProvider,
            ILoggerFactory loggerFactory)
        {
            IDataProtectionProvider dataProtectionProvider = null;
            dataProtectionProvider = new KeyRingBasedDataProtectionProvider(keyRingProvider, loggerFactory);

            // Link the provider to the supplied discriminator
            if (!string.IsNullOrEmpty(dpOptions.ApplicationDiscriminator))
            {
                dataProtectionProvider = dataProtectionProvider.CreateProtector(dpOptions.ApplicationDiscriminator);
            }

            return dataProtectionProvider;
        }

        internal static void PopulateDefaultOptions(KeyManagementOptions options, RegistryPolicyContext context, ILoggerFactory loggerFactory)
        {
            if (context != null)
            {
                if (context.DefaultKeyLifetime.HasValue)
                {
                    options.NewKeyLifetime = TimeSpan.FromDays(context.DefaultKeyLifetime.Value);
                }

                options.AuthenticatedEncryptorConfiguration = context.EncryptorConfiguration;

                var escrowSinks = context.KeyEscrowSinks;
                if (escrowSinks != null)
                {
                    options.KeyEscrowSinks.AddRange(escrowSinks);
                }
            }

            if (options.AuthenticatedEncryptorConfiguration == null)
            {
                options.AuthenticatedEncryptorConfiguration = new AuthenticatedEncryptorConfiguration();
            }

            var keyRepositoryEncryptorPair = GetKeyRepositoryEncryptorPair(loggerFactory);
            options.XmlRepository = keyRepositoryEncryptorPair.Key;
            options.XmlEncryptor = keyRepositoryEncryptorPair.Value;

            options.AuthenticatedEncryptorFactories.Add(new CngGcmAuthenticatedEncryptorFactory(options.AuthenticatedEncryptorConfiguration, loggerFactory));
            options.AuthenticatedEncryptorFactories.Add(new CngCbcAuthenticatedEncryptorFactory(options.AuthenticatedEncryptorConfiguration, loggerFactory));
            options.AuthenticatedEncryptorFactories.Add(new ManagedAuthenticatedEncryptorFactory(options.AuthenticatedEncryptorConfiguration, loggerFactory));
        }

        private static IKeyRingProvider GetKeyRingProvider(KeyManagementOptions kmOptions, ILoggerFactory loggerFactory, IActivator activator)
        {
            var keyRingProvider = new KeyRingProvider(
                    keyManager: GetKeyManager(kmOptions, loggerFactory, activator),
                    kmOptions: Options.Create(kmOptions),
                    defaultKeyResolver: GetDefaultKeyResolver(kmOptions, loggerFactory),
                    loggerFactory: loggerFactory);

            return keyRingProvider;
        }

        private static IDefaultKeyResolver GetDefaultKeyResolver(KeyManagementOptions kmOptions, ILoggerFactory loggerFactory)
        {
            return new DefaultKeyResolver(Options.Create(kmOptions), loggerFactory);
        }

        private static IKeyManager GetKeyManager(KeyManagementOptions kmOptions, ILoggerFactory loggerFactory, IActivator activator)
        {
            return new XmlKeyManager(
                keyManagementOptions: Options.Create(kmOptions),
                activator: activator,
                loggerFactory: loggerFactory);
        }

        private static IAuthenticatedEncryptorConfiguration GetAuthenticatedEncryptorConfiguration(RegistryPolicyContext registryPolicyContext)
        {
            return registryPolicyContext.EncryptorConfiguration;
        }

        private static IActivator GetDefaultActivator()
        {
            return SimpleActivator.DefaultWithoutServices;
        }

        internal static ILoggerFactory GetDefaultLoggerFactory()
        {
            return NullLoggerFactory.Instance;
        }

        internal static KeyValuePair<IXmlRepository, IXmlEncryptor> GetKeyRepositoryEncryptorPair(ILoggerFactory loggerFactory)
        {
            IXmlRepository repository = null;
            IXmlEncryptor encryptor = null;
            var log = loggerFactory.CreateLogger(typeof(DataProtectionProviderFactory));

            // If we're running in Azure Web Sites, the key repository goes in the %HOME% directory.
            var azureWebSitesKeysFolder = FileSystemXmlRepository.GetKeyStorageDirectoryForAzureWebSites();
            if (azureWebSitesKeysFolder != null)
            {
                log?.UsingAzureAsKeyRepository(azureWebSitesKeysFolder.FullName);

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
                        log?.UsingProfileAsKeyRepositoryWithDPAPI(localAppDataKeysFolder.FullName);
                    }
                    else
                    {
                        log?.UsingProfileAsKeyRepository(localAppDataKeysFolder.FullName);
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

                        log?.UsingRegistryAsKeyRepositoryWithDPAPI(regKeyStorageKey.Name);
                    }
                    else
                    {
                        // Final fallback - use an ephemeral repository since we don't know where else to go.
                        // This can only be used for development scenarios.
                        repository = new EphemeralXmlRepository(loggerFactory);

                        log?.UsingEphemeralKeyRepository();
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
