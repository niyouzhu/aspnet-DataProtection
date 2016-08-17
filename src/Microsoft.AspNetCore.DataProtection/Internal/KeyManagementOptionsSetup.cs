// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Cryptography.Cng;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.Cng;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;

namespace Microsoft.AspNetCore.DataProtection.Internal
{
    internal class KeyManagementOptionsSetup : IConfigureOptions<KeyManagementOptions>
    {
        private readonly RegistryPolicyResolver _registryPolicyResolver;
        private readonly ILoggerFactory _loggerFactory;

        public KeyManagementOptionsSetup(ILoggerFactory loggerFactory) : this(loggerFactory, registryPolicyResolver: null)
        {
        }

        public KeyManagementOptionsSetup(ILoggerFactory loggerFactory, RegistryPolicyResolver registryPolicyResolver)
        {
            _loggerFactory = loggerFactory;
            _registryPolicyResolver = registryPolicyResolver;
        }

        public void Configure(KeyManagementOptions options)
        {
            RegistryPolicy context = null;
            if (_registryPolicyResolver != null)
            {
                context = _registryPolicyResolver.ResolvePolicy();
            }

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

            var keyRepositoryEncryptorPair = GetKeyRepositoryEncryptorPair(_loggerFactory);
            options.XmlRepository = keyRepositoryEncryptorPair.Key;
            options.XmlEncryptor = keyRepositoryEncryptorPair.Value;

            options.AuthenticatedEncryptorFactories.Add(new CngGcmAuthenticatedEncryptorFactory(options.AuthenticatedEncryptorConfiguration, _loggerFactory));
            options.AuthenticatedEncryptorFactories.Add(new CngCbcAuthenticatedEncryptorFactory(options.AuthenticatedEncryptorConfiguration, _loggerFactory));
            options.AuthenticatedEncryptorFactories.Add(new ManagedAuthenticatedEncryptorFactory(options.AuthenticatedEncryptorConfiguration, _loggerFactory));
        }

        public static KeyValuePair<IXmlRepository, IXmlEncryptor> GetKeyRepositoryEncryptorPair(ILoggerFactory loggerFactory)
        {
            IXmlRepository repository = null;
            IXmlEncryptor encryptor = null;
            var log = loggerFactory.CreateLogger(typeof(KeyManagementOptionsSetup));

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
    }
}
