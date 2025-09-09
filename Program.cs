using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using ClientCertAuthDemo;
using System.Security.Cryptography.X509Certificates;
using Serilog;

// Configure Serilog for file and console logging
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("Logs/log-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

var builder = WebApplication.CreateBuilder(args);

// Use Serilog for logging
builder.Host.UseSerilog();

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Register the certificate chain validator
builder.Services.AddSingleton<CertificateChainValidator>();

// Configure client certificate authentication
builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options => {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.ValidateCertificateUse = true;
        options.ValidateValidityPeriod = true;
        
        // Revert to using CertificateChainValidator
        options.Events = new CertificateAuthenticationEvents {
            OnCertificateValidated = context => {
                var validator = context.HttpContext.RequestServices.GetRequiredService<CertificateChainValidator>();
                if (validator.ValidateCertificateWithSystemTrust(context.ClientCertificate))
                {
                    context.Success();
                }
                else
                {
                    context.Fail("Invalid client certificate: failed chain validation");
                }
                return Task.CompletedTask;
            }
        };
    });

// Configure authorization
builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
// Add this block before authentication
app.Use(async (context, next) =>
{
    if (context.Connection.ClientCertificate == null && context.Request.Headers.ContainsKey("X-ARR-ClientCert"))
    {
        var certHeader = context.Request.Headers["X-ARR-ClientCert"];
        if (!string.IsNullOrEmpty(certHeader))
        {
            var bytes = Convert.FromBase64String(certHeader);
            var cert = new X509Certificate2(bytes);
            context.Connection.ClientCertificate = cert;
        }
    }
    await next();
});
app.UseAuthentication();
app.UseAuthorization();

// Add secured endpoint requiring client certificate
app.MapGet("/api/secure", (HttpContext httpContext) => {
    var clientCert = httpContext.Connection.ClientCertificate;
    
    if (clientCert == null)
        return Results.Unauthorized();
        
    // Get certificate chain information for display
    using var chain = new X509Chain();
    chain.Build(clientCert);
    
    var chainElements = new List<object>();
    for (int i = 0; i < chain.ChainElements.Count; i++)
    {
        var element = chain.ChainElements[i];
        chainElements.Add(new {
            Subject = element.Certificate.Subject,
            Issuer = element.Certificate.Issuer,
            Thumbprint = element.Certificate.Thumbprint,
            ValidFrom = element.Certificate.NotBefore,
            ValidTo = element.Certificate.NotAfter
        });
    }
    
    return Results.Ok(new {
        Message = "Authentication successful with client certificate",
        Certificate = new {
            Subject = clientCert.Subject,
            Thumbprint = clientCert.Thumbprint,
            Issuer = clientCert.Issuer,
            ValidFrom = clientCert.NotBefore,
            ValidTo = clientCert.NotAfter,
            ChainInfo = new {
                Elements = chainElements,
                IsValid = chain.ChainStatus.Length == 0
            }
        }
    });
}).RequireAuthorization();

// Add test endpoint that doesn't require authentication
app.MapGet("/api/health", () => Results.Ok(new { Status = "Healthy", Timestamp = DateTime.UtcNow }));

app.Run();