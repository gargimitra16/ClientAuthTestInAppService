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

            _logger.LogInformation("[NewCode]:Starting certificate authentication. Checking for header: {HeaderName}", headerName);

            if (!Request.Headers.TryGetValue(headerName, out var certHeader) || string.IsNullOrWhiteSpace(certHeader))
            {
                _logger.LogWarning("Client certificate header missing or empty.");
                return Task.FromResult(AuthenticateResult.Fail("Client certificate header missing"));
            }

            try
            {
                
                // Open the CurrentUser's "Client Authentication Issuer" certificate store
                using (var store = new X509Store("ClientAuthIssuer", StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly);

                    foreach (var cert in store.Certificates)
                    {
                         _logger.LogInformation("[NewLog]:Found certificate in Client Authentication Issuer store:");
                            _logger.LogInformation("Subject: {Subject}", cert.Subject);
                            _logger.LogInformation("Thumbprint: {Thumbprint}", cert.Thumbprint);
                    }

                    store.Close();
                }

                _logger.LogInformation("Received certificate header: {CertHeader}", certHeader.ToString().Substring(0, Math.Min(30, certHeader.ToString().Length)) + "...");
                var certBytes = Convert.FromBase64String(certHeader);
                var clientCert = new X509Certificate2(certBytes);

                _logger.LogInformation("Parsed certificate subject: {Subject}", clientCert.Subject);
                _logger.LogInformation("Parsed certificate thumbprint: {Thumbprint}", clientCert.Thumbprint);
                

                    //var rootBytes = Convert.FromBase64String(rootBase64.Replace("\n", "").Replace("\r", "").Trim());
                    //var trustedRoot = new X509Certificate2(rootBytes);
                
                    var chain = new X509Chain();
                   // chain.ChainPolicy.ExtraStore.Add(trustedRoot);
                   // chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                // chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                //  chain.ChainPolicy.CustomTrustStore.Add(trustedRoot);
                //_logger.LogInformation("Loaded the root cert in CustomRootStore.SubjectName: {Subject}", trustedRoot.Subject);
                _logger.LogInformation("Starting to buildchain");
                bool isValid = chain.Build(clientCert);
                _logger.LogInformation("Certificate chain build result: {IsValid}", isValid);

                if (!isValid)
                {
                    var errors = string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()));
                    _logger.LogWarning("Certificate chain invalid: {Errors}", errors);
                    
                    foreach (X509ChainStatus status in chain.ChainStatus)
                    {
                        Console.WriteLine($"Status: {status.Status}, Info: {status.StatusInformation}");
                    }
                    return Task.FromResult(AuthenticateResult.Fail($"Certificate chain invalid: {errors}"));
                }

                //var trustedIssuer = "CN=MyRootCA";
                //if (!clientCert.Issuer.Contains(trustedIssuer))
                //{
                  //  _logger.LogWarning("Certificate not issued by trusted CA. Issuer: {Issuer}", clientCert.Issuer);
                //    return Task.FromResult(AuthenticateResult.Fail("Certificate not issued by trusted CA"));
              //  }

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
