using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Kentor.AuthServices
{
    /// <summary>
    /// Extension methods for XmlDocument
    /// </summary>
    public static class XmlDocumentExtensions
    {
        /// <summary>
        /// Sign an xml document with the supplied cert.
        /// </summary>
        /// <param name="xmlDocument">XmlDocument to be signed. The signature is
        /// added as a node in the document, right after the Issuer node.</param>
        /// <param name="cert">Certificate to use when signing.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1059:MembersShouldNotExposeCertainConcreteTypes", MessageId = "System.Xml.XmlNode")]
        public static void Sign(this XmlDocument xmlDocument, X509Certificate2 cert)
        {
            Sign(xmlDocument, cert, false);
        }

        /// <summary>
        /// Sign an xml document with the supplied cert.
        /// </summary>
        /// <param name="xmlDocument">XmlDocument to be signed. The signature is
        /// added as a node in the document, right after the Issuer node.</param>
        /// <param name="cert">Certificate to use when signing.</param>
        /// <param name="includeKeyInfo">Include public key in signed output.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1059:MembersShouldNotExposeCertainConcreteTypes", MessageId = "System.Xml.XmlNode")]
        public static void Sign(this XmlDocument xmlDocument, X509Certificate2 cert, bool includeKeyInfo)
        {
            if (xmlDocument == null)
            {
                throw new ArgumentNullException(nameof(xmlDocument));
            }

            if (cert == null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            var signedXml = new SignedXml(xmlDocument);

            // The transform XmlDsigExcC14NTransform and canonicalization method XmlDsigExcC14NTransformUrl is important for partially signed XML files
            // see: http://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.signedxml.xmldsigexcc14ntransformurl(v=vs.110).aspx
            // The reference URI has to be set correctly to avoid assertion injections
            // For both, the ID/Reference and the Transform/Canonicalization see as well: 
            // https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf section 5.4.2 and 5.4.3

            signedXml.SigningKey = (RSACryptoServiceProvider)cert.PrivateKey;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            var reference = new Reference { Uri = "#" + xmlDocument.DocumentElement.GetAttribute("ID") };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            signedXml.AddReference(reference);
            signedXml.ComputeSignature();

            if (includeKeyInfo)
            {
                var keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(cert));
                signedXml.KeyInfo = keyInfo;
            }

            xmlDocument.DocumentElement.InsertAfter(
                xmlDocument.ImportNode(signedXml.GetXml(), true),
                xmlDocument.DocumentElement["Issuer", Saml2Namespaces.Saml2Name]);
        }
        /// <summary>
        /// Sign an xml document with the supplied cert. using SHA-256
        /// </summary>
        /// <param name="xmlDocument">XmlDocument to be signed. The signature is
        /// added as a node in the document, right after the Issuer node.</param>
        /// <param name="cert">Certificate to use when signing.</param>
        /// <param name="includeKeyInfo">Include public key in signed output.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1059:MembersShouldNotExposeCertainConcreteTypes", MessageId = "System.Xml.XmlNode")]
        public static void Sign256(this XmlDocument xmlDocument, X509Certificate2 cert, bool includeKeyInfo)
        {
            if (xmlDocument == null)
            {
                throw new ArgumentNullException("xmlDocument");
            }

            if (cert == null)
            {
                throw new ArgumentNullException("cert");
            }


            // Note that this will return a Basic crypto provider, with only SHA-1 support
            var key = (RSACryptoServiceProvider)cert.PrivateKey;
            // Force use of the Enhanced RSA and AES Cryptographic Provider with openssl-generated SHA256 keys
            using (var cryptoProvider = new RSACryptoServiceProvider())
            {
                var enhCsp = cryptoProvider.CspKeyContainerInfo;
                var cspparams = new CspParameters(enhCsp.ProviderType, enhCsp.ProviderName, key.CspKeyContainerInfo.KeyContainerName);
                using (key = new RSACryptoServiceProvider(cspparams))
                {


                    var signedXml = new SignedXml(xmlDocument);
                    signedXml.SigningKey = key;
                    signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
                    signedXml.SignedInfo.SignatureMethod = @"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"; ;

                    var reference = new Reference { Uri = "#" + xmlDocument.DocumentElement.GetAttribute("ID") };
                    reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                    reference.AddTransform(new XmlDsigExcC14NTransform());

                    if (includeKeyInfo)
                    {
                        var keyInfo = new KeyInfo();
                        keyInfo.AddClause(new KeyInfoX509Data(cert));
                        signedXml.KeyInfo = keyInfo;
                    }

                    signedXml.AddReference(reference);
                    signedXml.ComputeSignature();
                    xmlDocument.DocumentElement.AppendChild(xmlDocument.ImportNode(signedXml.GetXml(), true));
                }
            }

        }

    }
}
