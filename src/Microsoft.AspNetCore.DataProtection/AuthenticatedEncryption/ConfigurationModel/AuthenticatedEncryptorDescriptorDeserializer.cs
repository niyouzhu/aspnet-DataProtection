// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Xml.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
    /// <summary>
    /// A class that can deserialize an <see cref="XElement"/> that represents the serialized version
    /// of an <see cref="AuthenticatedEncryptorDescriptor"/>.
    /// </summary>
    public sealed class AuthenticatedEncryptorDescriptorDeserializer : IAuthenticatedEncryptorDescriptorDeserializer
    {
        private readonly ILoggerFactory _loggerFactory;

        public AuthenticatedEncryptorDescriptorDeserializer()
            : this(services: null)
        {
        }

        public AuthenticatedEncryptorDescriptorDeserializer(IServiceProvider services)
        {
            _loggerFactory = services.GetRequiredService<ILoggerFactory>();
        }

        /// <summary>
        /// Imports the <see cref="AuthenticatedEncryptorDescriptor"/> from serialized XML.
        /// </summary>
        public IAuthenticatedEncryptorDescriptor ImportFromXml(XElement element)
        {
            if (element == null)
            {
                throw new ArgumentNullException(nameof(element));
            }

            // <descriptor>
            //   <encryption algorithm="..." />
            //   <validation algorithm="..." /> <!-- only if not GCM -->
            //   <masterKey requiresEncryption="true">...</masterKey>
            // </descriptor>

            var settings = new AuthenticatedEncryptionSettings();

            var encryptionElement = element.Element("encryption");
            settings.EncryptionAlgorithm = (EncryptionAlgorithm)Enum.Parse(typeof(EncryptionAlgorithm), (string)encryptionElement.Attribute("algorithm"));

            // only read <validation> if not GCM
            if (!AuthenticatedEncryptionSettings.IsGcmAlgorithm(settings.EncryptionAlgorithm))
            {
                var validationElement = element.Element("validation");
                settings.ValidationAlgorithm = (ValidationAlgorithm)Enum.Parse(typeof(ValidationAlgorithm), (string)validationElement.Attribute("algorithm"));
            }

            Secret masterKey = ((string)element.Elements("masterKey").Single()).ToSecret();
            return new AuthenticatedEncryptorDescriptor(settings, masterKey, _loggerFactory);
        }
    }
}
