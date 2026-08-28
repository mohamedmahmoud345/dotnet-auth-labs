namespace JwtFromScratch.Tests;

public class JwtFromScratchUnitTests
{
    [Fact]
    public void Encode_DecodesToValidBase64Url()
    {
        byte[] original = [72, 101, 108, 108, 111];

        string encoded = Base64Url.Encode(original);
        byte[] decoded = Base64Url.Decode(encoded);

        Assert.Equal(original, decoded);
    }

    [Fact]
    public void Decode_InvalidBase64UrlThrowsFormatException()
    {
        var input = "!!!invalid!!!";

        Assert.Throws<FormatException>(() => Base64Url.Decode(input));
    }

    [Fact]
    public void Decode_MissingPadding_HandleGracefully()
    {
        byte[] original = [72, 101, 108, 108, 111];

        string inputWithoutPadding = "SGVsbG8";

        var result = Base64Url.Decode(inputWithoutPadding);

        Assert.Equal(original, result);
    }
    
    [Fact]
    public void Encode_HandlesCharsRequiringUrlSafeReplacement()
    {
        byte[] data = [0xFB, 0xFF, 0xFE];
        string encoded = Base64Url.Encode(data);

        Assert.DoesNotContain('+', encoded);
        Assert.DoesNotContain('/', encoded);
        Assert.DoesNotContain('=', encoded);

        byte[] decoded = Base64Url.Decode(encoded);
        Assert.Equal(data, decoded);
    }
}
