## JWT from scratch

Backend-only authentication and authorization labs built from scratch.
HS256 JWT validation implemented without any JWT library.

### What's implemented

- **Base64Url** — encode/decode with URL-safe characters and padding handling
- **Token parsing** — split by `.`, validate exactly 3 parts
- **Header validation** — parse JSON, allow only HS256, reject alg:none
- **Signature validation** — HMAC-SHA256 with constant-time comparison
- **Claims validation** — exp, nbf, iat, iss, aud, sub

### Project structure

dotnet-auth-labs.slnx
src/
  JwtFromScratch/
    Base64Url.cs
    JwtToken.cs
tests/
  JwtFromScratch.Tests/
    JwtFromScratchUnitTests.cs
    CreateTestToken.cs

### Run tests

```bash
dotnet test
GitHub Actions workflow runs on push/PR to main — build, test, repeat.
