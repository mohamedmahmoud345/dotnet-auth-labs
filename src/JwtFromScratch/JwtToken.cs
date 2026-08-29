
using System.Text;
using System.Text.Json;

namespace JwtFromScratch;

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
}
