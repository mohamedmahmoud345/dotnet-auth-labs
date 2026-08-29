
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JwtFromScratch;

public record JwtClaims(
    string Sub,
    string? Iss,
    string? Aud,
    long? Exp,
    long? Nbf,
    long? Iat
);

public class JwtToken
{
    public string HeaderSegment { get; }
    public string PayloadSegment { get; }
    public string SignatureSegment { get; }
    private JwtToken(string header, string payload, string signature)
    {
        HeaderSegment = header;
        PayloadSegment = payload;
        SignatureSegment = signature;
    }

    public static JwtToken Parse(string input)
    {
        var parts = input.Split('.');
        if (!(parts.Length == 3))
            throw new FormatException("Invalid Token Structure");

        return new JwtToken(parts[0], parts[1], parts[2]);
    }

    public string GetAlgorithm()
    {
        var decodeHeader = Base64Url.Decode(HeaderSegment);
        var json = Encoding.UTF8.GetString(decodeHeader);
        string alg;
        try
        {
            using var doc = JsonDocument.Parse(json);
            alg = doc.RootElement.GetProperty("alg").GetString();
        }
        catch
        {
            throw new FormatException();
        }

        if (alg != "HS256")
            throw new FormatException();

        return alg!;
    }

    public void ValidateSignature(byte[] secret)
    {
        var signingInput = HeaderSegment + "." + PayloadSegment;
        var actualSig = Base64Url.Decode(SignatureSegment);

        byte[] expectedSignature = HMACSHA256.HashData(Encoding.UTF8.GetBytes(signingInput), secret);

        if (!FixedTimeEquals(expectedSignature, actualSig))
            throw new InvalidOperationException();
    }
    public JwtClaims ValidateClaims(string expectedIssuer, string expectedAudience)
    {
        var payload = Base64Url.Decode(PayloadSegment);
        var json = Encoding.UTF8.GetString(payload);
        using var doc = JsonDocument.Parse(json);

        if (doc.RootElement.TryGetProperty("iss", out JsonElement iss) && iss.ToString() != expectedIssuer)
            throw new InvalidOperationException();

        if (doc.RootElement.TryGetProperty("aud", out JsonElement aud) && aud.ToString() != expectedAudience)
            throw new InvalidOperationException();

        if (doc.RootElement.TryGetProperty("exp", out JsonElement exp) && DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp.GetInt64())
            throw new InvalidOperationException();

        if (doc.RootElement.TryGetProperty("nbf", out JsonElement nbf) && DateTimeOffset.UtcNow.ToUnixTimeSeconds() < nbf.GetInt64())
            throw new InvalidOperationException();

        if (doc.RootElement.TryGetProperty("iat", out JsonElement iat) && DateTimeOffset.UtcNow.ToUnixTimeSeconds() < iat.GetInt64())
            throw new InvalidOperationException();

        string sub = doc.RootElement.TryGetProperty("sub", out JsonElement subElement)
            ? subElement.GetString()!
            : "";

        return new JwtClaims(
            sub,
            doc.RootElement.TryGetProperty("iss", out var issEl) ? issEl.GetString() : null,
            doc.RootElement.TryGetProperty("aud", out var audEl) ? audEl.GetString() : null,
            doc.RootElement.TryGetProperty("exp", out var expEl) ? expEl.GetInt64() : null,
            doc.RootElement.TryGetProperty("nbf", out var nbfEl) ? nbfEl.GetInt64() : null,
            doc.RootElement.TryGetProperty("iat", out var iatEl) ? iatEl.GetInt64() : null
        );
    }

    private bool FixedTimeEquals(byte[] left, byte[] right)
    {
        if (left.Length != right.Length)
            return false;

        int result = 0;
        for (var i = 0; i < left.Length; i++)
        {
            result |= left[i] ^ right[i];
        }

        return result == 0;
    }
}
