using System.Security.Cryptography;
using System.Text;

namespace EncryptionUtil
{
    interface IRSAUtility
    {
        bool VerifyFileSignature(string filePath, string signaturePath, string publicKeyFile);
        string CreatePrivateKey(RSA rsa);
        string ExportPublicKey(RSA rsa);
    }

    class RSAUtility : IRSAUtility
    {
        /// <summary>
        /// Loads an RSA public key from an XML string.
        /// </summary>
        private static RSA LoadPublicKey(string xmlPublicKey)
        {
            RSA rsa = RSA.Create();
            rsa.ImportFromPem(xmlPublicKey);
            return rsa;
        }

        /// <summary>
        /// Verifies the signature of a file using RSA and SHA256.
        /// </summary>
        public bool VerifyFileSignature(string filePath, string signaturePath, string xmlPublicKey)
        {
            try
            {
                // Load public key
                using (RSA rsa = LoadPublicKey(xmlPublicKey))
                {
                    // Read file data
                    byte[] fileBytes = File.ReadAllBytes(filePath);

                    // Read signature bytes
                    byte[] signatureBytes = File.ReadAllBytes(signaturePath);

                    // Verify signature
                    return rsa.VerifyData(fileBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error verifying signature: {ex.Message}");
                return false;
            }
        }
        public string CreatePrivateKey(RSA rsa) 
        {
            
            var privateKeyBytes = rsa.ExportPkcs8PrivateKey();
            string base64Key = Convert.ToBase64String(privateKeyBytes);

            StringBuilder pem = new StringBuilder();
            pem.AppendLine("-----BEGIN PRIVATE KEY-----");
            for (int i = 0; i < base64Key.Length; i += 64)
            {
                pem.AppendLine(base64Key.Substring(i, Math.Min(64, base64Key.Length - i)));
            }
            pem.AppendLine("-----END PRIVATE KEY-----");
            return pem.ToString();
        }

        public string ExportPublicKey(RSA rsa)
        {
            var publicKeyBytes = rsa.ExportSubjectPublicKeyInfo(); // X.509 SPKI
            string base64Key = Convert.ToBase64String(publicKeyBytes);

            // Format with PEM headers
            StringBuilder pem = new StringBuilder();
            pem.AppendLine("-----BEGIN PUBLIC KEY-----");
            for (int i = 0; i < base64Key.Length; i += 64)
            {
                pem.AppendLine(base64Key.Substring(i, Math.Min(64, base64Key.Length - i)));
            }
            pem.AppendLine("-----END PUBLIC KEY-----");
            return pem.ToString();
        }

    }

    class NullRSAUtility : IRSAUtility
    {
        public bool VerifyFileSignature(string filePath, string signaturePath, string xmlPublicKey)
        {
            return true;
        }
        public string CreatePrivateKey(RSA rsa) { return string.Empty; }
        public string ExportPublicKey(RSA rsa) { return string.Empty; }
    }
    
}