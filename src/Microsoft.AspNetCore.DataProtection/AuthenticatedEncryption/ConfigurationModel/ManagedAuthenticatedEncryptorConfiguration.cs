// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
    /// <summary>
    /// Represents a configured authenticated encryption mechanism which uses
    /// managed <see cref="System.Security.Cryptography.SymmetricAlgorithm"/> and
    /// <see cref="System.Security.Cryptography.KeyedHashAlgorithm"/> types.
    /// </summary>
    public sealed class ManagedAuthenticatedEncryptorConfiguration : IAuthenticatedEncryptorConfiguration, IInternalAuthenticatedEncryptorConfiguration
    {
        /// <summary>
        /// The type of the algorithm to use for symmetric encryption.
        /// The type must subclass <see cref="SymmetricAlgorithm"/>.
        /// This property is required to have a value.
        /// </summary>
        /// <remarks>
        /// The algorithm must support CBC-style encryption and PKCS#7 padding and must have a block size of 64 bits or greater.
        /// The default algorithm is AES.
        /// </remarks>
        [ApplyPolicy]
        public Type EncryptionAlgorithmType { get; set; } = typeof(Aes);

        /// <summary>
        /// The length (in bits) of the key that will be used for symmetric encryption.
        /// This property is required to have a value.
        /// </summary>
        /// <remarks>
        /// The key length must be 128 bits or greater.
        /// The default value is 256.
        /// </remarks>
        [ApplyPolicy]
        public int EncryptionAlgorithmKeySize { get; set; } = 256;

        /// <summary>
        /// The type of the algorithm to use for validation.
        /// Type type must subclass <see cref="KeyedHashAlgorithm"/>.
        /// This property is required to have a value.
        /// </summary>
        /// <remarks>
        /// The algorithm must have a digest length of 128 bits or greater.
        /// The default algorithm is HMACSHA256.
        /// </remarks>
        [ApplyPolicy]
        public Type ValidationAlgorithmType { get; set; } = typeof(HMACSHA256);

        public IAuthenticatedEncryptorDescriptor CreateNewDescriptor()
        {
            return this.CreateNewDescriptorCore();
        }

        /// <summary>
        /// Validates that this <see cref="ManagedAuthenticatedEncryptorConfiguration"/> is well-formed, i.e.,
        /// that the specified algorithms actually exist and can be instantiated properly.
        /// An exception will be thrown if validation fails.
        /// </summary>
        public void Validate()
        {
            var factory = new ManagedAuthenticatedEncryptorFactory(this, DataProtectionProviderFactory.GetDefaultLoggerFactory());
            // Run a sample payload through an encrypt -> decrypt operation to make sure data round-trips properly.
            using (var encryptor = factory.CreateAuthenticatedEncryptorInstance(Secret.Random(512 / 8)))
            {
                encryptor.PerformSelfTest();
            }
        }

        IAuthenticatedEncryptorDescriptor IInternalAuthenticatedEncryptorConfiguration.CreateDescriptorFromSecret(ISecret secret)
        {
            return new ManagedAuthenticatedEncryptorDescriptor(this, secret);
        }
    }
}
