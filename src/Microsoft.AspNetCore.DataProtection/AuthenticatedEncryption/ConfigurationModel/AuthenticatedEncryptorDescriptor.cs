// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
    /// <summary>
    /// A descriptor which can create an authenticated encryption system based upon the
    /// configuration provided by an <see cref="AuthenticatedEncryptionSettings"/> object.
    /// </summary>
    public sealed class AuthenticatedEncryptorDescriptor : IAuthenticatedEncryptorDescriptor
    {
        private readonly ILoggerFactory _loggerFactory;

        public AuthenticatedEncryptorDescriptor(AuthenticatedEncryptionSettings settings, ISecret masterKey, ILoggerFactory loggerFactory)
        {
            if (settings == null)
            {
                throw new ArgumentNullException(nameof(settings));
            }

            if (masterKey == null)
            {
                throw new ArgumentNullException(nameof(masterKey));
            }

            Settings = settings;
            MasterKey = masterKey;
            _loggerFactory = loggerFactory;
        }

        internal ISecret MasterKey { get; }

        internal AuthenticatedEncryptionSettings Settings { get; }

        public IAuthenticatedEncryptor CreateEncryptorInstance()
        {
            return Settings.CreateAuthenticatedEncryptorInstance(MasterKey, _loggerFactory);
        }

        public XmlSerializedDescriptorInfo ExportToXml()
        {
            // <descriptor>
            //   <encryption algorithm="..." />
            //   <validation algorithm="..." /> <!-- only if not GCM -->
            //   <masterKey requiresEncryption="true">...</masterKey>
            // </descriptor>

            var encryptionElement = new XElement("encryption",
                new XAttribute("algorithm", Settings.EncryptionAlgorithm));

            var validationElement = (AuthenticatedEncryptionSettings.IsGcmAlgorithm(Settings.EncryptionAlgorithm))
                ? (object)new XComment(" AES-GCM includes a 128-bit authentication tag, no extra validation algorithm required. ")
                : (object)new XElement("validation",
                    new XAttribute("algorithm", Settings.ValidationAlgorithm));

            var outerElement = new XElement("descriptor",
                encryptionElement,
                validationElement,
                MasterKey.ToMasterKeyElement());

            return new XmlSerializedDescriptorInfo(outerElement, typeof(AuthenticatedEncryptorDescriptorDeserializer));
        }
    }
}
