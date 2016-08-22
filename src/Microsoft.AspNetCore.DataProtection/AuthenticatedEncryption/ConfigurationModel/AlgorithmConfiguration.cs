// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
    public abstract class AlgorithmConfiguration
    {
        internal const int KDK_SIZE_IN_BYTES = 512 / 8;

        /// <summary>
        /// Exports the current descriptor to XML.
        /// </summary>
        /// <returns>
        /// An <see cref="XmlSerializedDescriptorInfo"/> wrapping the <see cref="XElement"/> which represents the serialized
        /// current descriptor object. The deserializer type must be assignable to <see cref="IAuthenticatedEncryptorDescriptorDeserializer"/>.
        /// </returns>
        /// <remarks>
        /// If an element contains sensitive information (such as key material), the
        /// element should be marked via the <see cref="XmlExtensions.MarkAsRequiresEncryption(XElement)" />
        /// extension method, and the caller should encrypt the element before persisting
        /// the XML to storage.
        /// </remarks>
        public abstract IAuthenticatedEncryptorDescriptor CreateNewDescriptor();

        internal abstract IAuthenticatedEncryptorDescriptor CreateDescriptorFromSecret(ISecret secret);

        /// <summary>
        /// Performs a self-test of the algorithm specified by the configuration object.
        /// </summary>
        internal abstract void Validate();
    }
}
