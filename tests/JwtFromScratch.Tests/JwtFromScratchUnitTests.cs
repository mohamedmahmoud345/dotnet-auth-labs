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

    // jwt token part
    [Fact]
    public void Split_ValidToken_ReturnsThreeParts()
    {

        var token = "aaa.bbb.ccc";
        
        var res = JwtToken.Parse(token);

        Assert.Equal(res.HeaderSegment, "aaa");
        Assert.Equal(res.PayloadSegment, "bbb");
        Assert.Equal(res.SignatureSegment, "ccc");
    }
    [Fact]
    public void Split_InvalidToken_ThrowsFormatException()
    {
        var token1 = "aaa.bbb";
        var token2 = "aaa.bbb.ccc.ddd";


        Assert.Throws<FormatException>(() => JwtToken.Parse(token1));
        Assert.Throws<FormatException>(() => JwtToken.Parse(token2));
    }

    // three cases {invalid, null, none}

    [Fact]
    public void GetAlgorithm_ValidSegment_ReturnAlgorithm()
    {
        var encodedHeader = "eyJhbGciOiJIUzI1NiJ9.bbb.ccc";

        var jwtToken = JwtToken.Parse(encodedHeader);
        var algo = jwtToken.GetAlgorithm();

        Assert.Equal("HS256", algo);
    }

    [Fact]
    public void GetAlgorithm_InvalidAlgorithm_ThrowsFormatException()
    {
        var encodedHeader = "eyJhbGciOiJIMjU2In0.bbb.ccc";

        var jwtToken = JwtToken.Parse(encodedHeader);

        Assert.Throws<FormatException>(() => jwtToken.GetAlgorithm());
    }

    [Fact]
    public void GetAlgorithm_WithNone_ThrowsFormatException()
    {
        var encodedHeader = "eyJhbGciOiJub25lIn0.bbb.ccc";

        var jwtToken = JwtToken.Parse(encodedHeader);

        Assert.Throws<FormatException>(() => jwtToken.GetAlgorithm());
    }

    [Fact]
    public void GetAlgorithm_WithMissingAlgorithm_ThrowsKeyNotFoundException()
    {
        var encodedHeader = "e30=.bbb.ccc";

        var jwtToken = JwtToken.Parse(encodedHeader);

        Assert.Throws<KeyNotFoundException>(() => jwtToken.GetAlgorithm());
    }
}
