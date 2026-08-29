
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
}
