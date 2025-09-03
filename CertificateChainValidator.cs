using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace ClientCertAuthDemo
{
    public class CertificateChainValidator
    {
        private readonly ILogger<CertificateChainValidator> _logger;
        private readonly X509Certificate2Collection _trustedCaCertificates;

        public CertificateChainValidator(ILogger<CertificateChainValidator> logger)
        {
            _logger = logger;
            _trustedCaCertificates = LoadTrustedCaCertificates();
        }

        public bool ValidateCertificate(X509Certificate2 clientCertificate)
        {
            if (clientCertificate == null)
            {
                _logger.LogWarning("Certificate validation failed: Certificate is null");
                return false;
            }

            _logger.LogInformation("Validating certificate: Subject={Subject}, Thumbprint={Thumbprint}, Issuer={Issuer}", 
                clientCertificate.Subject, clientCertificate.Thumbprint, clientCertificate.Issuer);

            using var chain = new X509Chain
            {
                ChainPolicy = 
                {
                    RevocationMode = X509RevocationMode.Online,
                    RevocationFlag = X509RevocationFlag.EntireChain,
                    VerificationFlags = X509VerificationFlags.NoFlag
                }
            };

            // Add trusted CA certificates to the chain's extra store
            foreach (var caCert in _trustedCaCertificates)
            {
                chain.ChainPolicy.ExtraStore.Add(caCert);
                _logger.LogDebug("Added trusted CA certificate to chain: {Subject}", caCert.Subject);
            }

            bool isChainValid = chain.Build(clientCertificate);

            if (!isChainValid)
            {
                foreach (var status in chain.ChainStatus)
                {
                    _logger.LogWarning("Certificate chain validation error: {Status} - {StatusInformation}", 
                        status.Status, status.StatusInformation);
                }
                return false;
            }

            // Additional validation: Verify the root certificate is in our trusted collection
            if (chain.ChainElements.Count > 0)
            {
                var rootCert = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                bool isTrustedRoot = IsCertificateInTrustedCollection(rootCert);

                if (!isTrustedRoot)
                {
                    _logger.LogWarning("Certificate validation failed: Root certificate is not trusted. Root Subject={Subject}, Thumbprint={Thumbprint}", 
                        rootCert.Subject, rootCert.Thumbprint);
                    return false;
                }
            }

            _logger.LogInformation("Certificate validation successful");
            return true;
        }

        private bool IsCertificateInTrustedCollection(X509Certificate2 certificate)
        {
            foreach (var trustedCert in _trustedCaCertificates)
            {
                if (certificate.Thumbprint.Equals(trustedCert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        private X509Certificate2Collection LoadTrustedCaCertificates()
        {
            var collection = new X509Certificate2Collection();
            
            // Load trusted CA certificates from environment variable
            var caCertBase64 = Environment.GetEnvironmentVariable("TRUSTED_CA_CERT");
            if (!string.IsNullOrEmpty(caCertBase64))
            {
                try 
                {
                    var certBytes = Convert.FromBase64String(caCertBase64);
                    var cert = new X509Certificate2(certBytes);
                    collection.Add(cert);
                    _logger.LogInformation("Loaded CA certificate from environment variable: Subject={Subject}, Thumbprint={Thumbprint}", 
                        cert.Subject, cert.Thumbprint);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error loading CA certificate from environment variable");
                }
            }
            else
            {
                _logger.LogWarning("No trusted CA certificates found in environment variable 'TRUSTED_CA_CERT'");
            }
            
            return collection;
        }
    }
}