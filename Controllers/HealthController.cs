using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;

namespace ClientCertAuthDemo.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class HealthController : ControllerBase
    {
        [Authorize(AuthenticationSchemes = "CertificateHeader")]
        [HttpGet]
        public IActionResult Get()
        {
            var subject = User.Identity?.Name ?? "anonymous";
            var thumbprint = User.Claims.FirstOrDefault(c => c.Type == "Thumbprint")?.Value ?? "none";
            return Ok(new { status = "healthy", certificateSubject = subject, certificateThumbprint = thumbprint });
        }
    }
}
