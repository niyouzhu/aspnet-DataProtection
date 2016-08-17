// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection
{
    /// <summary>
    /// Contains static factory methods for creating <see cref="IDataProtectionProvider"/> instances.
    /// </summary>
    internal static class DataProtectionProviderFactory
    {
        public static ILoggerFactory GetDefaultLoggerFactory()
        {
            return NullLoggerFactory.Instance;
        }

        //public static IDataProtectionProvider Create(DataProtectionOptions dpOptions, KeyManagementOptions kmOptions, ILoggerFactory loggerFactory, IActivator activator)
        //{
        //    if (dpOptions == null)
        //    {
        //        throw new ArgumentNullException(nameof(dpOptions));
        //    }

        //    if (kmOptions == null)
        //    {
        //        throw new ArgumentNullException(nameof(kmOptions));
        //    }

        //    loggerFactory = loggerFactory ?? GetDefaultLoggerFactory();
        //    activator = activator ?? GetDefaultActivator();
        //    RegistryPolicy registryPolicyContext = null;
        //    if (OSVersionUtil.IsWindows())
        //    {
        //        registryPolicyContext = RegistryPolicyResolver.ResolveDefaultPolicy(activator, loggerFactory);
        //    }

        //    PopulateDefaultOptions(kmOptions, registryPolicyContext, loggerFactory);

        //    var keyRingProvider = GetKeyRingProvider(kmOptions, loggerFactory, activator);

        //    return Create(dpOptions, keyRingProvider, loggerFactory);
        //}

        //public static IDataProtectionProvider Create(
        //    DataProtectionOptions dpOptions,
        //    IKeyRingProvider keyRingProvider,
        //    ILoggerFactory loggerFactory)
        //{
        //    IDataProtectionProvider dataProtectionProvider = null;
        //    dataProtectionProvider = new KeyRingBasedDataProtectionProvider(keyRingProvider, loggerFactory);

        //    // Link the provider to the supplied discriminator
        //    if (!string.IsNullOrEmpty(dpOptions.ApplicationDiscriminator))
        //    {
        //        dataProtectionProvider = dataProtectionProvider.CreateProtector(dpOptions.ApplicationDiscriminator);
        //    }

        //    return dataProtectionProvider;
        //}

        //private static IKeyRingProvider GetKeyRingProvider(KeyManagementOptions kmOptions, ILoggerFactory loggerFactory, IActivator activator)
        //{
        //    var keyRingProvider = new KeyRingProvider(
        //            keyManager: GetKeyManager(kmOptions, loggerFactory, activator),
        //            kmOptions: Options.Create(kmOptions),
        //            defaultKeyResolver: GetDefaultKeyResolver(kmOptions, loggerFactory),
        //            loggerFactory: loggerFactory);

        //    return keyRingProvider;
        //}

        //private static IDefaultKeyResolver GetDefaultKeyResolver(KeyManagementOptions kmOptions, ILoggerFactory loggerFactory)
        //{
        //    return new DefaultKeyResolver(Options.Create(kmOptions), loggerFactory);
        //}

        //private static IKeyManager GetKeyManager(KeyManagementOptions kmOptions, ILoggerFactory loggerFactory, IActivator activator)
        //{
        //    return new XmlKeyManager(
        //        keyManagementOptions: Options.Create(kmOptions),
        //        activator: activator,
        //        loggerFactory: loggerFactory);
        //}

        //private static IAuthenticatedEncryptorConfiguration GetAuthenticatedEncryptorConfiguration(RegistryPolicy registryPolicyContext)
        //{
        //    return registryPolicyContext.EncryptorConfiguration;
        //}

        //private static IActivator GetDefaultActivator()
        //{
        //    return SimpleActivator.DefaultWithoutServices;
        //}
    }
}
