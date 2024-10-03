using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using ITfoxtec.Identity.Saml2;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();
// Add services to the container.
builder.Services.AddControllers();
//builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c => { c.SwaggerDoc("v1", new OpenApiInfo { Title = "SAML2 API", Version = "v1" }); });

// Add CORS policies

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins",
        builder => builder.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader());
});

X509Certificate2 cert;
if (builder.Configuration["Saml2:IdpCertFilePath"] == "true")
{
    builder.Configuration.AddJsonFile("cert/cert.json", optional: true, reloadOnChange: true);
    var pemPath = "cert/cert.pem";
    var pemCertData = System.IO.File.ReadAllText(pemPath);
    pemCertData = pemCertData.Replace("-----BEGIN CERTIFICATE-----", string.Empty)
        .Replace("-----END CERTIFICATE-----", string.Empty).Trim();

// Convert from Base64 to byte array
    var certBytes = Convert.FromBase64String(pemCertData);
    cert = new X509Certificate2(certBytes);
}
else
{
    var certData = Convert.FromBase64String(builder.Configuration["Saml2:IdpCertificate"]);
    cert = new X509Certificate2(certData);
}

// Configure SAML2
builder.Services.Configure<Saml2Configuration>(saml2Configuration =>
{
    saml2Configuration.Issuer = builder.Configuration["Saml2:Issuer"];
    saml2Configuration.SingleSignOnDestination = new Uri(builder.Configuration["Saml2:IdpSsoUrl"]);
    saml2Configuration.SingleLogoutDestination = new Uri(builder.Configuration["Saml2:IdpSloUrl"]);
    saml2Configuration.SignatureValidationCertificates.Add(cert);
    saml2Configuration.AllowedAudienceUris.Add(builder.Configuration["Saml2:Issuer"]);
    saml2Configuration.SignAuthnRequest = false; // Authentication Request Signed: No
    saml2Configuration.CertificateValidationMode = X509CertificateValidationMode.None;
    saml2Configuration.RevocationMode = X509RevocationMode.NoCheck;
});

builder.Services.AddSaml2();
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = builder.Configuration["Jwt:Issuer"],
                ValidAudience = builder.Configuration["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
            };
        }
    )
    ;

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "SAML2 API v1"));
}

app.UseHttpsRedirection();
app.UseRouting();

//app.UseCors("AllowSpecificOrigin"); // Apply CORS policies
// use default CORS policy for testing purposes
app.UseCors("AllowAllOrigins");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();