using System.IdentityModel.Tokens.Jwt;
using System.Security.Authentication;
using System.Security.Claims;
using System.Text;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreSamlClient.Controllers;

/// <summary>
/// Controller responsible for handling authentication using SAML2.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController(IOptions<Saml2Configuration> configAccessor, IConfiguration configuration)
    : ControllerBase
{
    /// <summary>
    /// Holds the configuration settings for SAML2 authentication.
    /// This configuration is used to read and write SAML2 messages,
    /// handle SAML2 responses, and manage SAML2 sessions within the
    /// AuthController.
    /// </summary>
    private readonly Saml2Configuration _config = configAccessor.Value;

    /// <summary>
    /// Initiates the SAML login process by generating a SAML authentication request and binding it to a redirect URL.
    /// </summary>
    /// <param name="returnUrl">The URL to which the user should be redirected after a successful login. Defaults to root ("/") if not specified.</param>
    /// <returns>Returns an IActionResult that initiates the SAML login process by redirecting the user to the identity provider's login page.</returns>
    [HttpGet("saml/login")]
    public IActionResult Login(string? returnUrl = null)
    {
        var binding = new Saml2RedirectBinding();
        binding.SetRelayStateQuery(new Dictionary<string, string> { { "ReturnUrl", returnUrl ?? "/" } });
        var actionResult = binding.Bind(new Saml2AuthnRequest(_config)).ToActionResult();
        return actionResult;
    }

    /// <summary>
    /// Processes SAML assertions from the Identity Provider (IdP). Reads the SAML response, validates it, creates a session,
    /// and generates a JWT token based on the SAML claims.
    /// </summary>
    /// <returns>Returns an IActionResult which contains a JWT token in the response body if the SAML authentication is successful.</returns>
    [HttpPost("/auth/saml")]
    public async Task<IActionResult> AssertionConsumerService()
    {
        var binding = new Saml2PostBinding();
        var saml2AuthnResponse = new Saml2AuthnResponse(_config);

        binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);
        
        if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
        {
            throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
        }
        binding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnResponse);
        await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(claimsPrincipal));

        var token = GenerateJwtToken(saml2AuthnResponse.ClaimsIdentity);
        return Ok(new { Token = token });
    }

    /// Initiates a SAML single logout request.
    /// The method constructs a SAML Logout Request and binds it to a redirect location,
    /// sending the user to the appropriate identity provider for logout.
    /// Upon successful logout from the identity provider, the user will be redirected
    /// back to the specified location or the application's default redirect URI.
    /// <return>
    /// A redirect action result that sends the user to the identity provider's logout endpoint.
    /// </return>
    [HttpGet("saml/logout")]
    public IActionResult SamlLogout()
    {
        var binding = new Saml2RedirectBinding();
        var saml2LogoutRequest = new Saml2LogoutRequest(_config);
        binding.Bind(saml2LogoutRequest);
        return Redirect(binding.RedirectLocation.ToString());
    }

    /// <summary>
    /// Generates a JSON Web Token (JWT) for the given ClaimsIdentity.
    /// </summary>
    /// <param name="identity">The ClaimsIdentity for which the JWT is to be generated.</param>
    /// <returns>A string representing the generated JWT.</returns>
    private string GenerateJwtToken(ClaimsIdentity identity)
    {
        var claims = identity.Claims.ToList();

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: configuration["Jwt:Issuer"],
            audience: configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}