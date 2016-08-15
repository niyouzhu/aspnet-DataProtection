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
    public class CngCbcAuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
    {
        private readonly ILogger _logger;
        private readonly CngCbcAuthenticatedEncryptorConfiguration _configuration;

        public CngCbcAuthenticatedEncryptorFactory(IAuthenticatedEncryptorConfiguration configuration, ILoggerFactory loggerFactory)
        {
            _configuration =  configuration as CngCbcAuthenticatedEncryptorConfiguration ?? GetRequiredConfiguration(configuration);
            _logger = loggerFactory?.CreateLogger<CngCbcAuthenticatedEncryptorDescriptor>();
        }

        public IAuthenticatedEncryptor CreateEncryptorInstance(IKey key)
        {
            var descriptor = key.Descriptor as CngCbcAuthenticatedEncryptorDescriptor;
            if (descriptor == null)
            {
                return null;
            }

            return CreateAuthenticatedEncryptorInstance(descriptor.MasterKey);
        }

        internal CbcAuthenticatedEncryptor CreateAuthenticatedEncryptorInstance(ISecret secret)
        {
            if (_configuration == null)
            {
                return null;
            }

            return new CbcAuthenticatedEncryptor(
                keyDerivationKey: new Secret(secret),
                symmetricAlgorithmHandle: GetSymmetricBlockCipherAlgorithmHandle(),
                symmetricAlgorithmKeySizeInBytes: (uint)(_configuration.EncryptionAlgorithmKeySize / 8),
                hmacAlgorithmHandle: GetHmacAlgorithmHandle());
        }

        private CngCbcAuthenticatedEncryptorConfiguration GetRequiredConfiguration(IAuthenticatedEncryptorConfiguration configuration)
        {
            var authenticatedConfiguration = configuration as AuthenticatedEncryptorConfiguration;
            if (authenticatedConfiguration == null)
            {
                return null;
            }

            if (!authenticatedConfiguration.IsGcmAlgorithm() && OSVersionUtil.IsWindows())
            {
                return new CngCbcAuthenticatedEncryptorConfiguration()
                {
                    EncryptionAlgorithm = authenticatedConfiguration.GetBCryptAlgorithmNameFromEncryptionAlgorithm(),
                    EncryptionAlgorithmKeySize = authenticatedConfiguration.GetAlgorithmKeySizeInBits(),
                    HashAlgorithm = authenticatedConfiguration.GetBCryptAlgorithmNameFromValidationAlgorithm()
                };
            }

            return null;
        }

        private BCryptAlgorithmHandle GetHmacAlgorithmHandle()
        {
            // basic argument checking
            if (String.IsNullOrEmpty(_configuration.HashAlgorithm))
            {
                throw Error.Common_PropertyCannotBeNullOrEmpty(nameof(_configuration.HashAlgorithm));
            }

            _logger?.OpeningCNGAlgorithmFromProviderWithHMAC(_configuration.HashAlgorithm, _configuration.HashAlgorithmProvider);
            BCryptAlgorithmHandle algorithmHandle = null;

            // Special-case cached providers
            if (_configuration.HashAlgorithmProvider == null)
            {
                if (_configuration.HashAlgorithm == Constants.BCRYPT_SHA1_ALGORITHM) { algorithmHandle = CachedAlgorithmHandles.HMAC_SHA1; }
                else if (_configuration.HashAlgorithm == Constants.BCRYPT_SHA256_ALGORITHM) { algorithmHandle = CachedAlgorithmHandles.HMAC_SHA256; }
                else if (_configuration.HashAlgorithm == Constants.BCRYPT_SHA512_ALGORITHM) { algorithmHandle = CachedAlgorithmHandles.HMAC_SHA512; }
            }

            // Look up the provider dynamically if we couldn't fetch a cached instance
            if (algorithmHandle == null)
            {
                algorithmHandle = BCryptAlgorithmHandle.OpenAlgorithmHandle(_configuration.HashAlgorithm, _configuration.HashAlgorithmProvider, hmac: true);
            }

            // Make sure we're using a hash algorithm. We require a minimum 128-bit digest.
            uint digestSize = algorithmHandle.GetHashDigestLength();
            AlgorithmAssert.IsAllowableValidationAlgorithmDigestSize(checked(digestSize * 8));

            // all good!
            return algorithmHandle;
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

            _logger?.OpeningCNGAlgorithmFromProviderWithChainingModeCBC(_configuration.EncryptionAlgorithm, _configuration.EncryptionAlgorithmProvider);

            BCryptAlgorithmHandle algorithmHandle = null;

            // Special-case cached providers
            if (_configuration.EncryptionAlgorithmProvider == null)
            {
                if (_configuration.EncryptionAlgorithm == Constants.BCRYPT_AES_ALGORITHM) { algorithmHandle = CachedAlgorithmHandles.AES_CBC; }
            }

            // Look up the provider dynamically if we couldn't fetch a cached instance
            if (algorithmHandle == null)
            {
                algorithmHandle = BCryptAlgorithmHandle.OpenAlgorithmHandle(_configuration.EncryptionAlgorithm, _configuration.EncryptionAlgorithmProvider);
                algorithmHandle.SetChainingMode(Constants.BCRYPT_CHAIN_MODE_CBC);
            }

            // make sure we're using a block cipher with an appropriate key size & block size
            AlgorithmAssert.IsAllowableSymmetricAlgorithmBlockSize(checked(algorithmHandle.GetCipherBlockLength() * 8));
            AlgorithmAssert.IsAllowableSymmetricAlgorithmKeySize(checked((uint)_configuration.EncryptionAlgorithmKeySize));

            // make sure the provided key length is valid
            algorithmHandle.GetSupportedKeyLengths().EnsureValidKeyLength((uint)_configuration.EncryptionAlgorithmKeySize);

            // all good!
            return algorithmHandle;
        }
    }
}
