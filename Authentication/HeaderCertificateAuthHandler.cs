using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;

namespace ClientCertAuthDemo.Authentication
{
    public class HeaderCertificateAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
#pragma warning disable CS0618 // 'SystemClock' is obsolete
        public HeaderCertificateAuthHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder)
            : base(options, loggerFactory, encoder, new SystemClock())
        {
            _logger = loggerFactory.CreateLogger<HeaderCertificateAuthHandler>();
        }
#pragma warning restore CS0618

        private readonly ILogger _logger;

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            const string headerName = "X-ARR-ClientCert";

            _logger.LogInformation("Starting certificate authentication. Checking for header: {HeaderName}", headerName);

            if (!Request.Headers.TryGetValue(headerName, out var certHeader) || string.IsNullOrWhiteSpace(certHeader))
            {
                _logger.LogWarning("Client certificate header missing or empty.");
                return Task.FromResult(AuthenticateResult.Fail("Client certificate header missing"));
            }

            try
            {
                _logger.LogInformation("Received certificate header: {CertHeader}", certHeader.ToString().Substring(0, Math.Min(30, certHeader.ToString().Length)) + "...");
                var certBytes = Convert.FromBase64String(certHeader);
                var clientCert = new X509Certificate2(certBytes);

                _logger.LogInformation("Parsed certificate subject: {Subject}", clientCert.Subject);
                _logger.LogInformation("Parsed certificate thumbprint: {Thumbprint}", clientCert.Thumbprint);

                // 🔍 Build chain manually
                var chain = new X509Chain();
                chain.ChainPolicy = new X509ChainPolicy
                {
                    RevocationMode = X509RevocationMode.NoCheck, // 🚫 Skip CRL/OCSP
                    // RevocationFlag = X509RevocationFlag.ExcludeRoot,
                    VerificationFlags = X509VerificationFlags.NoFlag,
                    TrustMode = X509ChainTrustMode.System,
                    ApplicationPolicy = { new Oid("1.3.6.1.5.5.7.3.2") } // Optional: Client Auth EKU
                };

                bool isValid = chain.Build(clientCert);
                _logger.LogInformation("Certificate chain build result: {IsValid}", isValid);

                if (!isValid)
                {
                    var errors = string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()));
                    _logger.LogWarning("Certificate chain invalid: {Errors}", errors);
                    return Task.FromResult(AuthenticateResult.Fail($"Certificate chain invalid: {errors}"));
                }

                var trustedIssuer = "CN=MyRootCA";
                if (!clientCert.Issuer.Contains(trustedIssuer))
                {
                    _logger.LogWarning("Certificate not issued by trusted CA. Issuer: {Issuer}", clientCert.Issuer);
                    return Task.FromResult(AuthenticateResult.Fail("Certificate not issued by trusted CA"));
                }

                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, clientCert.Subject),
                    new Claim("Thumbprint", clientCert.Thumbprint)
                };

                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);

                _logger.LogInformation("Certificate authentication succeeded for subject: {Subject}", clientCert.Subject);
                return Task.FromResult(AuthenticateResult.Success(ticket));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Certificate parsing or validation failed: {Message}", ex.Message);
                return Task.FromResult(AuthenticateResult.Fail($"Certificate parsing failed: {ex.Message}"));
            }
        }
    }
}
