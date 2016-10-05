// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Cryptography.Cng;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
    public class AuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
    {
        private readonly ILoggerFactory _loggerFactory;
        private readonly AuthenticatedEncryptorConfiguration _authenticatedConfiguration;

        public AuthenticatedEncryptorFactory(AlgorithmConfiguration configuration, ILoggerFactory loggerFactory)
        {
            _authenticatedConfiguration = configuration as AuthenticatedEncryptorConfiguration;
            _loggerFactory = loggerFactory;
        }

        public IAuthenticatedEncryptor CreateEncryptorInstance(IKey key)
        {
            var descriptor = key.Descriptor as AuthenticatedEncryptorDescriptor;
            if (descriptor == null)
            {
                return null;
            }

            return CreateAuthenticatedEncryptorInstance(descriptor.MasterKey);
        }

        internal IAuthenticatedEncryptor CreateAuthenticatedEncryptorInstance(ISecret secret)
        {
            if (_authenticatedConfiguration == null)
            {
                return null;
            }

            if (_authenticatedConfiguration.IsGcmAlgorithm())
            {
                // GCM requires CNG, and CNG is only supported on Windows.
                if (!OSVersionUtil.IsWindows())
                {
                    throw new PlatformNotSupportedException(Resources.Platform_WindowsRequiredForGcm);
                }

                var configuration = new CngGcmAuthenticatedEncryptorConfiguration()
                {
                    EncryptionAlgorithm = _authenticatedConfiguration.GetBCryptAlgorithmNameFromEncryptionAlgorithm(),
                    EncryptionAlgorithmKeySize = _authenticatedConfiguration.GetAlgorithmKeySizeInBits()
                };

                return new CngGcmAuthenticatedEncryptorFactory(configuration, _loggerFactory).CreateAuthenticatedEncryptorInstance(secret);
            }
            else
            {
                if (OSVersionUtil.IsWindows())
                {
                    // CNG preferred over managed implementations if running on Windows
                    var configuration = new CngCbcAuthenticatedEncryptorConfiguration()
                    {
                        EncryptionAlgorithm = _authenticatedConfiguration.GetBCryptAlgorithmNameFromEncryptionAlgorithm(),
                        EncryptionAlgorithmKeySize = _authenticatedConfiguration.GetAlgorithmKeySizeInBits(),
                        HashAlgorithm = _authenticatedConfiguration.GetBCryptAlgorithmNameFromValidationAlgorithm()
                    };

                    return new CngCbcAuthenticatedEncryptorFactory(configuration, _loggerFactory).CreateAuthenticatedEncryptorInstance(secret);
                }
                else
                {
                    // Use managed implementations as a fallback
                    var configuration = new ManagedAuthenticatedEncryptorConfiguration()
                    {
                        EncryptionAlgorithmType = _authenticatedConfiguration.GetManagedTypeFromEncryptionAlgorithm(),
                        EncryptionAlgorithmKeySize = _authenticatedConfiguration.GetAlgorithmKeySizeInBits(),
                        ValidationAlgorithmType = _authenticatedConfiguration.GetManagedTypeFromValidationAlgorithm()
                    };

                    return new ManagedAuthenticatedEncryptorFactory(configuration, _loggerFactory).CreateAuthenticatedEncryptorInstance(secret);
                }
            }
        }
    }
}
