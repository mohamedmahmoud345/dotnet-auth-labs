
namespace JwtFromScratch;

public static class JwtToken
{
    public static (string, string, string) SplitToken(string input)
    {
        var sp = input.Split('.');
        if (!(sp.Length == 3))
            throw new FormatException("Invalid Token Structure");

        return (sp[0], sp[1], sp[2]);
    }

}
