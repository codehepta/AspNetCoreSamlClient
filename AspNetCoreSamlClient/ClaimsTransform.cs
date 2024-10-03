using System.Security.Claims;

namespace AspNetCoreSamlClient;

public static class ClaimsTransform
{
    public static ClaimsPrincipal Transform(ClaimsPrincipal incomingPrincipal)
    {
        if (!incomingPrincipal.Identity.IsAuthenticated)
        {
            return incomingPrincipal;
        }

        var claims = new List<Claim>();

        // SAML claim'lerini JWT claim'lerine dönüştür
        foreach (var claim in incomingPrincipal.Claims)
        {
            switch (claim.Type)
            {
                case ClaimTypes.NameIdentifier:
                    claims.Add(new Claim("sub", claim.Value));
                    break;
                case ClaimTypes.Email:
                    claims.Add(new Claim("email", claim.Value));
                    break;
                case ClaimTypes.GivenName:
                    claims.Add(new Claim("given_name", claim.Value));
                    break;
                case ClaimTypes.Surname:
                    claims.Add(new Claim("family_name", claim.Value));
                    break;
                // Diğer claim dönüşümlerini buraya ekleyin
                default:
                    claims.Add(claim);
                    break;
            }
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, incomingPrincipal.Identity.AuthenticationType));
    }
}