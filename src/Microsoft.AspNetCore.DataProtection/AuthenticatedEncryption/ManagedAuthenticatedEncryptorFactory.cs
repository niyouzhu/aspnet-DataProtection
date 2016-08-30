// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.Cng;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Managed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
    public class ManagedAuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
    {
        private readonly ILogger _logger;
        private readonly ManagedAuthenticatedEncryptorConfiguration _configuration;

        public ManagedAuthenticatedEncryptorFactory(AlgorithmConfiguration configuration, ILoggerFactory loggerFactory)
        {
            _configuration = configuration as ManagedAuthenticatedEncryptorConfiguration ?? GetRequiredConfiguration(configuration);
            _logger = loggerFactory?.CreateLogger<ManagedAuthenticatedEncryptorFactory>();
        }

        public IAuthenticatedEncryptor CreateEncryptorInstance(IKey key)
        {
            var descriptor = key.Descriptor as ManagedAuthenticatedEncryptorDescriptor;
            if (descriptor == null)
            {
                return null;
            }

            return CreateAuthenticatedEncryptorInstance(descriptor.MasterKey);
        }

        internal ManagedAuthenticatedEncryptor CreateAuthenticatedEncryptorInstance(ISecret secret)
        {
            if (_configuration == null)
            {
                return null;
            }

            return new ManagedAuthenticatedEncryptor(
                keyDerivationKey: new Secret(secret),
                symmetricAlgorithmFactory: GetSymmetricBlockCipherAlgorithmFactory(),
                symmetricAlgorithmKeySizeInBytes: _configuration.EncryptionAlgorithmKeySize / 8,
                validationAlgorithmFactory: GetKeyedHashAlgorithmFactory());
        }

        private ManagedAuthenticatedEncryptorConfiguration GetRequiredConfiguration(AlgorithmConfiguration configuration)
        {
            var authenticatedConfiguration = configuration as AuthenticatedEncryptorConfiguration;
            if (authenticatedConfiguration == null)
            {
                return null;
            }

            if (!authenticatedConfiguration.IsGcmAlgorithm() && !OSVersionUtil.IsWindows())
            {
                return new ManagedAuthenticatedEncryptorConfiguration()
                {
                    EncryptionAlgorithmType = authenticatedConfiguration.GetManagedTypeFromEncryptionAlgorithm(),
                    EncryptionAlgorithmKeySize = authenticatedConfiguration.GetAlgorithmKeySizeInBits(),
                    ValidationAlgorithmType = authenticatedConfiguration.GetManagedTypeFromValidationAlgorithm()
                };
            }

            return null;
        }

        private Func<KeyedHashAlgorithm> GetKeyedHashAlgorithmFactory()
        {
            // basic argument checking
            if (_configuration.ValidationAlgorithmType == null)
            {
                throw Error.Common_PropertyCannotBeNullOrEmpty(nameof(_configuration.ValidationAlgorithmType));
            }

            _logger?.UsingManagedKeyedHashAlgorithm(_configuration.ValidationAlgorithmType.FullName);
            if (_configuration.ValidationAlgorithmType == typeof(HMACSHA256))
            {
                return () => new HMACSHA256();
            }
            else if (_configuration.ValidationAlgorithmType == typeof(HMACSHA512))
            {
                return () => new HMACSHA512();
            }
            else
            {
                return AlgorithmActivator.CreateFactory<KeyedHashAlgorithm>(_configuration.ValidationAlgorithmType);
            }
        }

        private Func<SymmetricAlgorithm> GetSymmetricBlockCipherAlgorithmFactory()
        {
            // basic argument checking
            if (_configuration.EncryptionAlgorithmType == null)
            {
                throw Error.Common_PropertyCannotBeNullOrEmpty(nameof(_configuration.EncryptionAlgorithmType));
            }
            typeof(SymmetricAlgorithm).AssertIsAssignableFrom(_configuration.EncryptionAlgorithmType);
            if (_configuration.EncryptionAlgorithmKeySize < 0)
            {
                throw Error.Common_PropertyMustBeNonNegative(nameof(_configuration.EncryptionAlgorithmKeySize));
            }

            _logger?.UsingManagedSymmetricAlgorithm(_configuration.EncryptionAlgorithmType.FullName);

            if (_configuration.EncryptionAlgorithmType == typeof(Aes))
            {
                Func<Aes> factory = null;
#if !NETSTANDARD1_3
                if (OSVersionUtil.IsWindows())
                {
                    // If we're on desktop CLR and running on Windows, use the FIPS-compliant implementation.
                    factory = () => new AesCryptoServiceProvider();
                }
#endif
                return factory ?? Aes.Create;
            }
            else
            {
                return AlgorithmActivator.CreateFactory<SymmetricAlgorithm>(_configuration.EncryptionAlgorithmType);
            }
        }

        /// <summary>
        /// Contains helper methods for generating cryptographic algorithm factories.
        /// </summary>
        private static class AlgorithmActivator
        {
            /// <summary>
            /// Creates a factory that wraps a call to <see cref="Activator.CreateInstance{T}"/>.
            /// </summary>
            public static Func<T> CreateFactory<T>(Type implementation)
            {
                return ((IActivator<T>)Activator.CreateInstance(typeof(AlgorithmActivatorCore<>).MakeGenericType(implementation))).Creator;
            }

            private interface IActivator<out T>
            {
                Func<T> Creator { get; }
            }

            private class AlgorithmActivatorCore<T> : IActivator<T> where T : new()
            {
                public Func<T> Creator { get; } = Activator.CreateInstance<T>;
            }
        }
    }
}
