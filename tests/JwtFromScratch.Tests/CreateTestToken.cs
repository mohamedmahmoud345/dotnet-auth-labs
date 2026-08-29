
using System.Security.Cryptography;
using System.Text;

namespace JwtFromScratch.Tests;

public static class CreateTestToken
{
    public static string Create(string header, string payload, byte[] secret)
    {
        var signingInput = $"{Base64Url.Encode(Encoding.UTF8.GetBytes(header))}.{Base64Url.Encode(Encoding.UTF8.GetBytes(payload))}";
        var signature = HMACSHA256.HashData(Encoding.UTF8.GetBytes(signingInput), secret);

        return $"{signingInput}.{Base64Url.Encode(signature)}";
    }
    public static string CreateTokenWithClaims(byte[] secret)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return CreateTestToken.Create(
            "{\"alg\":\"HS256\"}",
            $$"""
        {
            "sub": "alice",
            "iss": "my-app",
            "aud": "my-api",
            "exp": {{now + 3600}},
            "nbf": {{now}},
            "iat": {{now}}
        }
        """,
            secret);
    }
}
