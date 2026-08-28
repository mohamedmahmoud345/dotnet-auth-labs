
namespace JwtFromScratch;

public static class Base64Url
{
    public static string Encode(byte[] data)
    {
        string base64 = Convert.ToBase64String(data);

        base64 = base64.Replace('+', '-').Replace('/', '_');

        return base64.TrimEnd('=');
    }

    public static byte[] Decode(string input)
    {
        if (string.IsNullOrEmpty(input))
            throw new FormatException("Invalid Base64Url input");


        var padding = 4 - (input.Length % 4);
        if (padding != 4)
            input = input + new string('=', padding);

        input = input.Replace('-', '+').Replace('_', '/');

        return Convert.FromBase64String(input);
    }
}
