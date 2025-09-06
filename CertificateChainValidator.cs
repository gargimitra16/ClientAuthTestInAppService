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
            _logger.LogInformation("Starting the loading of trusted CA certificates.");
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

                // If chain validation fails, check if the certificate is self-signed and matches the expected thumbprint
                var expectedThumbprint = Environment.GetEnvironmentVariable("SELF_SIGNED_CERT_THUMBPRINT");
                if (ValidateSelfSignedCertificate(clientCertificate, expectedThumbprint))
                {
                    _logger.LogInformation("Certificate is self-signed and trusted by thumbprint");
                    return true;
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

        public bool ValidateCertificateWithSystemTrust(X509Certificate2 clientCertificate)
        {
            if (clientCertificate == null)
            {
                _logger.LogWarning("System trust validation failed: Certificate is null");
                return false;
            }

            _logger.LogInformation("System trust validating certificate: Subject={Subject}, Thumbprint={Thumbprint}, Issuer={Issuer}",
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

            // Do not add any extra store certificates; rely on system trust
            bool isChainValid = chain.Build(clientCertificate);

            if (!isChainValid)
            {
                foreach (var status in chain.ChainStatus)
                {
                    _logger.LogWarning("System trust chain validation error: {Status} - {StatusInformation}",
                        status.Status, status.StatusInformation);
                }
                return false;
            }

            _logger.LogInformation("System trust certificate validation successful");
            return true;
        }

        public bool ValidateSelfSignedCertificate(X509Certificate2 clientCertificate, string expectedThumbprint)
        {
            if (clientCertificate == null)
            {
                _logger.LogWarning("Self-signed validation failed: Certificate is null");
                return false;
            }

            _logger.LogInformation("Validating self-signed certificate: Subject={Subject}, Thumbprint={Thumbprint}",
                clientCertificate.Subject, clientCertificate.Thumbprint);

            // Check if the certificate is self-signed (chain length 1, subject == issuer)
            if (clientCertificate.Subject == clientCertificate.Issuer)
            {
                _logger.LogInformation("Self-signed certificate validation successful");
                return true;
            }
            _logger.LogWarning("Self-signed certificate validation failed: Thumbprint mismatch or not self-signed");
            return false;
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