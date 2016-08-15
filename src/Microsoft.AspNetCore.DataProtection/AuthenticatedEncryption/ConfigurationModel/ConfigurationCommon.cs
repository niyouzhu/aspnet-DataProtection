// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
    internal static class ConfigurationCommon
    {
        /// <summary>
        /// Creates an <see cref="IAuthenticatedEncryptorDescriptor"/> from this <see cref="IInternalAuthenticatedEncryptorConfiguration"/>
        /// using a random 512-bit master key generated from a secure PRNG.
        /// </summary>
        public static IAuthenticatedEncryptorDescriptor CreateNewDescriptorCore(this IInternalAuthenticatedEncryptorConfiguration configuration)
        {
            const int KDK_SIZE_IN_BYTES = 512 / 8;
            return configuration.CreateDescriptorFromSecret(Secret.Random(KDK_SIZE_IN_BYTES));
        }

        public static bool IsGcmAlgorithm(this AuthenticatedEncryptorConfiguration configuration)
        {
            var algorithm = configuration.EncryptionAlgorithm;
            return (EncryptionAlgorithm.AES_128_GCM <= algorithm && algorithm <= EncryptionAlgorithm.AES_256_GCM);
        }

        public static int GetAlgorithmKeySizeInBits(this AuthenticatedEncryptorConfiguration configuration)
        {
            var algorithm = configuration.EncryptionAlgorithm;
            switch (algorithm)
            {
                case EncryptionAlgorithm.AES_128_CBC:
                case EncryptionAlgorithm.AES_128_GCM:
                    return 128;

                case EncryptionAlgorithm.AES_192_CBC:
                case EncryptionAlgorithm.AES_192_GCM:
                    return 192;

                case EncryptionAlgorithm.AES_256_CBC:
                case EncryptionAlgorithm.AES_256_GCM:
                    return 256;

                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm));
            }
        }

        public static string GetBCryptAlgorithmNameFromEncryptionAlgorithm(this AuthenticatedEncryptorConfiguration configuration)
        {
            var algorithm = configuration.EncryptionAlgorithm;
            switch (algorithm)
            {
                case EncryptionAlgorithm.AES_128_CBC:
                case EncryptionAlgorithm.AES_192_CBC:
                case EncryptionAlgorithm.AES_256_CBC:
                case EncryptionAlgorithm.AES_128_GCM:
                case EncryptionAlgorithm.AES_192_GCM:
                case EncryptionAlgorithm.AES_256_GCM:
                    return Constants.BCRYPT_AES_ALGORITHM;

                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm));
            }
        }

        public static string GetBCryptAlgorithmNameFromValidationAlgorithm(this AuthenticatedEncryptorConfiguration configuration)
        {
            var algorithm = configuration.ValidationAlgorithm;
            switch (algorithm)
            {
                case ValidationAlgorithm.HMACSHA256:
                    return Constants.BCRYPT_SHA256_ALGORITHM;

                case ValidationAlgorithm.HMACSHA512:
                    return Constants.BCRYPT_SHA512_ALGORITHM;

                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm));
            }
        }

        public static Type GetManagedTypeFromEncryptionAlgorithm(this AuthenticatedEncryptorConfiguration configuration)
        {
            var algorithm = configuration.EncryptionAlgorithm;
            switch (algorithm)
            {
                case EncryptionAlgorithm.AES_128_CBC:
                case EncryptionAlgorithm.AES_192_CBC:
                case EncryptionAlgorithm.AES_256_CBC:
                case EncryptionAlgorithm.AES_128_GCM:
                case EncryptionAlgorithm.AES_192_GCM:
                case EncryptionAlgorithm.AES_256_GCM:
                    return typeof(Aes);

                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm));
            }
        }

        public static Type GetManagedTypeFromValidationAlgorithm(this AuthenticatedEncryptorConfiguration configuration)
        {
            var algorithm = configuration.ValidationAlgorithm;
            switch (algorithm)
            {
                case ValidationAlgorithm.HMACSHA256:
                    return typeof(HMACSHA256);

                case ValidationAlgorithm.HMACSHA512:
                    return typeof(HMACSHA512);

                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm));
            }
        }
    }
}
