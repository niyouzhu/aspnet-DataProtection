// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Cryptography;
using Microsoft.AspNetCore.Cryptography.Cng;
using Microsoft.AspNetCore.Cryptography.SafeHandles;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.Cng;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
    public class CngGcmAuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
    {
        private readonly ILogger _logger;
        private readonly CngGcmAuthenticatedEncryptorConfiguration _configuration;

        public CngGcmAuthenticatedEncryptorFactory(IAuthenticatedEncryptorConfiguration configuration, ILoggerFactory loggerFactory)
        {
            _configuration = configuration as CngGcmAuthenticatedEncryptorConfiguration ?? GetRequiredConfiguration(configuration);
            _logger = loggerFactory?.CreateLogger<CngGcmAuthenticatedEncryptorDescriptor>();
        }

        public IAuthenticatedEncryptor CreateEncryptorInstance(IKey key)
        {
            var descriptor = key.Descriptor as CngGcmAuthenticatedEncryptorDescriptor;
            if (descriptor == null)
            {
                return null;
            }

            return CreateAuthenticatedEncryptorInstance(descriptor.MasterKey);
        }

        internal GcmAuthenticatedEncryptor CreateAuthenticatedEncryptorInstance(ISecret secret)
        {
            if (_configuration == null)
            {
                return null;
            }

            return new GcmAuthenticatedEncryptor(
                keyDerivationKey: new Secret(secret),
                symmetricAlgorithmHandle: GetSymmetricBlockCipherAlgorithmHandle(),
                symmetricAlgorithmKeySizeInBytes: (uint)(_configuration.EncryptionAlgorithmKeySize / 8));
        }

        private CngGcmAuthenticatedEncryptorConfiguration GetRequiredConfiguration(IAuthenticatedEncryptorConfiguration configuration)
        {
            var authenticatedConfiguration = configuration as AuthenticatedEncryptorConfiguration;
            if (authenticatedConfiguration == null)
            {
                return null;
            }

            if (authenticatedConfiguration.IsGcmAlgorithm())
            {
                // GCM requires CNG, and CNG is only supported on Windows.
                if (!OSVersionUtil.IsWindows())
                {
                    throw new PlatformNotSupportedException(Resources.Platform_WindowsRequiredForGcm);
                }
                return new CngGcmAuthenticatedEncryptorConfiguration()
                {
                    EncryptionAlgorithm = authenticatedConfiguration.GetBCryptAlgorithmNameFromEncryptionAlgorithm(),
                    EncryptionAlgorithmKeySize = authenticatedConfiguration.GetAlgorithmKeySizeInBits()
                };
            }

            return null;
        }

        private BCryptAlgorithmHandle GetSymmetricBlockCipherAlgorithmHandle()
        {
            // basic argument checking
            if (String.IsNullOrEmpty(_configuration.EncryptionAlgorithm))
            {
                throw Error.Common_PropertyCannotBeNullOrEmpty(nameof(EncryptionAlgorithm));
            }
            if (_configuration.EncryptionAlgorithmKeySize < 0)
            {
                throw Error.Common_PropertyMustBeNonNegative(nameof(_configuration.EncryptionAlgorithmKeySize));
            }

            BCryptAlgorithmHandle algorithmHandle = null;

            _logger?.OpeningCNGAlgorithmFromProviderWithChainingModeGCM(_configuration.EncryptionAlgorithm, _configuration.EncryptionAlgorithmProvider);
            // Special-case cached providers
            if (_configuration.EncryptionAlgorithmProvider == null)
            {
                if (_configuration.EncryptionAlgorithm == Constants.BCRYPT_AES_ALGORITHM) { algorithmHandle = CachedAlgorithmHandles.AES_GCM; }
            }

            // Look up the provider dynamically if we couldn't fetch a cached instance
            if (algorithmHandle == null)
            {
                algorithmHandle = BCryptAlgorithmHandle.OpenAlgorithmHandle(_configuration.EncryptionAlgorithm, _configuration.EncryptionAlgorithmProvider);
                algorithmHandle.SetChainingMode(Constants.BCRYPT_CHAIN_MODE_GCM);
            }

            // make sure we're using a block cipher with an appropriate key size & block size
            CryptoUtil.Assert(algorithmHandle.GetCipherBlockLength() == 128 / 8, "GCM requires a block cipher algorithm with a 128-bit block size.");
            AlgorithmAssert.IsAllowableSymmetricAlgorithmKeySize(checked((uint)_configuration.EncryptionAlgorithmKeySize));

            // make sure the provided key length is valid
            algorithmHandle.GetSupportedKeyLengths().EnsureValidKeyLength((uint)_configuration.EncryptionAlgorithmKeySize);

            // all good!
            return algorithmHandle;
        }
    }
}
