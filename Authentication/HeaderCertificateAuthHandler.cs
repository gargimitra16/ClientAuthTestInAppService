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
                
                
                    const string rootBase64 = @"MIIFpTCCA42gAwIBAgIUCOq4tfeRt+EIwngQHxFbW0yURHQwDQYJKoZIhvcNAQEL
BQAwYjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdSZWRtb25k
MQ4wDAYDVQQKDAVNeU9yZzERMA8GA1UECwwIU2VjdXJpdHkxETAPBgNVBAMMCE15
Um9vdENBMB4XDTI1MDkwODE3MDIxOVoXDTM1MDkwNjE3MDIxOVowYjELMAkGA1UE
BhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdSZWRtb25kMQ4wDAYDVQQKDAVN
eU9yZzERMA8GA1UECwwIU2VjdXJpdHkxETAPBgNVBAMMCE15Um9vdENBMIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3E+zTXVa3WGu8nU72WEPuuaiHd7L
xW7oCGtDhRrUvnNyI2TPqQVx+G4JS1aUNwYQsV7wCT2xksnGhe+cxKYgmPvb5nXQ
EUOsC4GqKhvxS2i3Y5uTjzbBvr0aqfG2AxBMPzURI6GCTAS1EgA99OQqmw8o9vQV
2z++0YGjQNi1OKbtBeDs7GUUrafiWqiwBZigNEAUyHELJCzPdGcjoj/aqD+MzMop
3dQ1biUYS0y1HACczdjii7L99wSdFJigP2pl8a4jcCjH9hNondNf//Tyvtg3WAbK
O/X1xDTVBKdBlZBEOQ5xbpHAQsuh6WdWYVY+pmgDTG1V97llp7O3U6NE7+2IJCbr
0AZoGpUcDCQsbGauSPOnLlenOoSuzTEJHEQ2J4dw3AfXv2E182KlILCSjcpEMjlT
xx552Opqs1CoiAgB2oF2Aa/Kvt8LdKLJ7BItZwhNmGXYyCJPZVreEQn57dh83h9Q
XvZG5XuDqm7FkvKhxIq5Y0hqf3n5xysKyM+jZxU/vCDoV0oQBGsuJtNXoAyb1qVz
VGE1F4GY2JeDiqiqnVwyn0OtVmuBVbPfn4fm5YBYN1x6Jt0VHaIUFJavn9H7kxPC
T4Mfi1SeoMIYicOLICwZ6F4lywo0eUE8oWQtNqQVLv8h2nlu9vqAaaCBFL360ill
fCBpRXGTPbbWlv0CAwEAAaNTMFEwHQYDVR0OBBYEFL6hYJv3LxPfenLObA0ScCWG
5mbYMB8GA1UdIwQYMBaAFL6hYJv3LxPfenLObA0ScCWG5mbYMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggIBAA7jZbeq2HZ6/gRWQBgpMbSbWmGpCRmp
/basTmuPlQd9/1mX3UwybjAo3hILrBf6nQuzcmC8nJj9AaxCdTvKQSGmrvr5XmZZ
VLhbB8pCoo+cABT3N6vqoIV2i3YhhL78hq5ycgzgQKRn/Xj1s5TIiMvMHw669FPg
LarzqH6sd3DKvVPwxN0X56mMaX9DACByqYp3Q80MoB2Fd5hNxU+6n48yZ74m94wx
hr01NyJh95Jf6CuXKCrvC2EXh08/b8pyxUL2xdUOvRpc5i/i9O+AC7KG35rAscLm
qJSt3wiNcoOgBNlTOJ0mgCPyP7HbdzZuIO4FxsvItD8O9rCilKo6BXARXFksRQMp
aDOhJuNsaUjVnT4fXxAYNRq2U6X9Bz++QaAXfrwzgOErsg8z62ay++iP0D/bKSPK
iRSs5MbzLxz0/UL04lRcoyWRd7nfXgu+pJRWc41X2hCp9zbMJKKo4kxAFwgbeiW1
y6rIaSuPW2uJq36HNYfJnjSy8JbqaG2YkKzrg0Tl149003UbHpNRQippl15M2XOC
35IKgv4GowbczKswTxbFQV637VxzFbHD+etP1j8WLFkLeCZOXXAWnios5TaEjC3I
MySxDEyNm9dQBjkrgCR7doeAJE5cfIJqhJAJSG812iT6+uQivJJaq5A+mTq8zqrh
TZ4NYuiCby7v"; // Truncated for brevity

                    var rootBytes = Convert.FromBase64String(rootBase64.Replace("\n", "").Replace("\r", "").Trim());
                    var trustedRoot = new X509Certificate2(rootBytes);
                
                    var chain = new X509Chain();
                   // chain.ChainPolicy.ExtraStore.Add(trustedRoot);
                   // chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(trustedRoot);
                _logger.LogInformation("Loaded the root cert in CustomRootStore.SubjectName: {Subject}", trustedRoot.Subject);
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
