// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Cryptography.Cng;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
    /// <summary>
    /// Represents a generalized authenticated encryption mechanism.
    /// </summary>
    public sealed class AuthenticatedEncryptorConfiguration : IAuthenticatedEncryptorConfiguration, IInternalAuthenticatedEncryptorConfiguration
    {
        /// <summary>
        /// The algorithm to use for symmetric encryption (confidentiality).
        /// </summary>
        /// <remarks>
        /// The default value is <see cref="EncryptionAlgorithm.AES_256_CBC"/>.
        /// </remarks>
        public EncryptionAlgorithm EncryptionAlgorithm { get; set; } = EncryptionAlgorithm.AES_256_CBC;

        /// <summary>
        /// The algorithm to use for message authentication (tamper-proofing).
        /// </summary>
        /// <remarks>
        /// The default value is <see cref="ValidationAlgorithm.HMACSHA256"/>.
        /// This property is ignored if <see cref="EncryptionAlgorithm"/> specifies a 'GCM' algorithm.
        /// </remarks>
        public ValidationAlgorithm ValidationAlgorithm { get; set; } = ValidationAlgorithm.HMACSHA256;

        public IAuthenticatedEncryptorDescriptor CreateNewDescriptor()
        {
            return this.CreateNewDescriptorCore();
        }

        public void Validate()
        {
            var loggerFactory = DataProtectionProviderFactory.GetDefaultLoggerFactory();
            var sampleSecret = Secret.Random(512 / 8);
            IAuthenticatedEncryptor encryptor = null;

            try
            {
                // Run a sample payload through an encrypt -> decrypt operation to make sure data round-trips properly.
                if (this.IsGcmAlgorithm())
                {
                    // GCM requires CNG, and CNG is only supported on Windows.
                    if (!OSVersionUtil.IsWindows())
                    {
                        throw new PlatformNotSupportedException(Resources.Platform_WindowsRequiredForGcm);
                    }
                    encryptor = new CngGcmAuthenticatedEncryptorFactory(this, loggerFactory).CreateAuthenticatedEncryptorInstance(sampleSecret);
                }
                else
                {
                    if (OSVersionUtil.IsWindows())
                    {
                        // CNG preferred over managed implementations if running on Windows
                        encryptor = new CngCbcAuthenticatedEncryptorFactory(this, loggerFactory).CreateAuthenticatedEncryptorInstance(sampleSecret);
                    }
                    else
                    {
                        // Use managed implementations as a fallback
                        encryptor = new ManagedAuthenticatedEncryptorFactory(this, loggerFactory).CreateAuthenticatedEncryptorInstance(sampleSecret);
                    }
                }

                encryptor.PerformSelfTest();
            }
            finally
            {
                (encryptor as IDisposable)?.Dispose();
            }
        }

        IAuthenticatedEncryptorDescriptor IInternalAuthenticatedEncryptorConfiguration.CreateDescriptorFromSecret(ISecret secret)
        {
            return new AuthenticatedEncryptorDescriptor(this, secret);
        }
    }
}
