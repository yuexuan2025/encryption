using System.Security.Cryptography;
using System.Text;
using YuexuanCrypto.Core.Crypto;

namespace YuexuanCrypto.Core.Format;

/// <summary>
/// 密码提示区：位于加密头之后的可选明文旁路，经软件因子混淆。
/// 无密码、无本软件则无法还原；本软件可在解密前展示。
/// </summary>
public static class HintStore
{
    // 布局: marker "YXH1"(4) + len u32 + obfuscated bytes
    private static readonly byte[] Marker = "YXH1"u8.ToArray();

    public static byte[] Encode(string? hint)
    {
        if (string.IsNullOrWhiteSpace(hint))
        {
            return [];
        }
        var obfuscated = HintCodec.Obfuscate(hint!);
        var data = Encoding.UTF8.GetBytes(obfuscated);
        var output = new byte[4 + 4 + data.Length];
        Marker.CopyTo(output, 0);
        BitConverter.TryWriteBytes(output.AsSpan(4, 4), data.Length);
        data.CopyTo(output, 8);
        return output;
    }

    public static string? Decode(ReadOnlySpan<byte> blob)
    {
        if (blob.Length < 8)
        {
            return null;
        }
        if (!blob[..4].SequenceEqual(Marker))
        {
            return null;
        }
        int len = BitConverter.ToInt32(blob.Slice(4, 4));
        if (len < 0 || blob.Length < 8 + len)
        {
            return null;
        }
        var obfuscated = Encoding.UTF8.GetString(blob.Slice(8, len));
        return HintCodec.Deobfuscate(obfuscated);
    }
}
