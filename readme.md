# SAML2 API Example Project

## Introduction
This example project is an ASP.NET Core application that provides 
SAML2 authentication and JWT token generation functionality. 
It enables seamless integration with Identity Providers (IdPs) that support SAML2,
while also supporting JWT for API security.
I couldn't find any suitable examples like this, so I wanted to contribute my findings to the open source community.

## Table of Contents
1. [Installation](#installation)
2. [Usage](#usage)
3. [Features](#features)
4. [Contributing](#contributing)
5. [License](#license)
6. [Acknowledgements](#acknowledgements)

## Installation
To set up the project locally, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/your-repository.git
   cd your-repository
   ```

2. Install dependencies:
   ```bash
   dotnet restore
   ```

3. Build the project:
   ```bash
   dotnet build
   ```

## Usage
To run and use the application:

1. Run the application:
   ```bash
   dotnet run
   ```

2. Open your browser and navigate to `http://localhost:5000` (or the specified port).

### Configuration
Make sure to update the `appsettings.json` file with your specific configurations for SAML2 and JWT:
```json
{
  "Saml2": {
    "Issuer": "your-api-here",
    "IdpSsoUrl": "https://your-idp-adress-here/Account/SamlLoginRedirect",
    "IdpSloUrl": "https://your-idp-adress-here/Account/SamlLogoutRedirect",
    "IdpCertificate": "certificate-signing-hash-here",
    "AssertionConsumerServiceUrl": "https://your-api-here/api/auth/saml",
    "SingleLogoutUrl": "https://your-api-here/api/saml/logout",
    "NameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "IdpCertFilePath": "cert/cert.pem",
    "UseIdpCertFile": "false"
  },
  "Jwt": {
    "Key": "your-secret-key-here-your-secret-key-here-your-secret-key-her",
    "Issuer": "your-issuer",
    "Audience": "your-audience"
  }
}
```

### Controllers
The `AuthController` handles SAML authentication and JWT token generation:
```csharp
class AuthController:
  IActionResult Login(string? returnUrl = null)
  Task<IActionResult> AssertionConsumerService()
  IActionResult SamlLogout()
  string GenerateJwtToken(ClaimsIdentity identity)
```

### Claims Transformation
The `ClaimsTransform` class transforms SAML claims into JWT claims:
```csharp
public static class ClaimsTransform
{
    public static ClaimsPrincipal Transform(ClaimsPrincipal incomingPrincipal)
    {
        if (!incomingPrincipal.Identity.IsAuthenticated)
        {
            return incomingPrincipal;
        }

        var claims = new List<Claim>();

        // SAML claim to JWT claim transformation
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
                default:
                    claims.Add(claim);
                    break;
            }
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, incomingPrincipal.Identity.AuthenticationType));
    }
}
```

## Features
- SAML2 Authentication
- JWT Token Generation
- Configurable Identity Provider (IdP) settings
- Swagger API documentation
- CORS policy support

## Contributing
If you wish to contribute to this project, follow these steps:
- Fork the repository.
- Create a new branch (`git checkout -b feature/feature-name`).
- Commit your changes (`git commit -m 'Add some feature'`).
- Push to the branch (`git push origin feature/feature-name`).
- Open a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.

## Acknowledgements
- Libraries: [ITfoxtec.Identity.Saml2](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2) and [Swashbuckle.AspNetCore](https://github.com/domaindrivendev/Swashbuckle.AspNetCore)