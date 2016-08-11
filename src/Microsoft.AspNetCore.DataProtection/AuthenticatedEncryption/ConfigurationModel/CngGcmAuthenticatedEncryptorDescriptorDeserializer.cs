// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Xml.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
    /// <summary>
    /// A class that can deserialize an <see cref="XElement"/> that represents the serialized version
    /// of an <see cref="CngGcmAuthenticatedEncryptorDescriptor"/>.
    /// </summary>
    public sealed class CngGcmAuthenticatedEncryptorDescriptorDeserializer : IAuthenticatedEncryptorDescriptorDeserializer
    {
        private readonly ILoggerFactory _loggerFactory;

        public CngGcmAuthenticatedEncryptorDescriptorDeserializer()
            : this(services: null)
        {
        }

        public CngGcmAuthenticatedEncryptorDescriptorDeserializer(IServiceProvider services)
        {
            _loggerFactory = services.GetRequiredService<ILoggerFactory>();
        }

        /// <summary>
        /// Imports the <see cref="CngCbcAuthenticatedEncryptorDescriptor"/> from serialized XML.
        /// </summary>
        public IAuthenticatedEncryptorDescriptor ImportFromXml(XElement element)
        {
            if (element == null)
            {
                throw new ArgumentNullException(nameof(element));
            }

            // <descriptor>
            //   <!-- Windows CNG-GCM -->
            //   <encryption algorithm="..." keyLength="..." [provider="..."] />
            //   <masterKey>...</masterKey>
            // </descriptor>

            var settings = new CngGcmAuthenticatedEncryptionSettings();

            var encryptionElement = element.Element("encryption");
            settings.EncryptionAlgorithm = (string)encryptionElement.Attribute("algorithm");
            settings.EncryptionAlgorithmKeySize = (int)encryptionElement.Attribute("keyLength");
            settings.EncryptionAlgorithmProvider = (string)encryptionElement.Attribute("provider"); // could be null

            Secret masterKey = ((string)element.Element("masterKey")).ToSecret();

            return new CngGcmAuthenticatedEncryptorDescriptor(settings, masterKey, _loggerFactory);
        }
    }
}
