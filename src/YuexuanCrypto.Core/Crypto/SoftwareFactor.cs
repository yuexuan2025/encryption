using System.Security.Cryptography;

namespace YuexuanCrypto.Core.Crypto;

/// <summary>
/// 软件内置密钥因子。多层拆分 + AES 解密还原，提高静态扫描/简单反编译门槛。
/// 注意：无法抵御拥有本软件二进制的完整逆向；目标是抬高自动化提取成本。
/// </summary>
internal static class SoftwareFactor
{
    // 四段异或碎片（非完整因子）
    private static readonly byte[] P0 =
    {
        0x6B, 0x21, 0xC4, 0x09, 0x5E, 0xA7, 0x13, 0xD8,
        0x4F, 0x92, 0x0C, 0xE5, 0x77, 0x3A, 0xB1, 0x58
    };

    private static readonly byte[] P1 =
    {
        0x02, 0xDF, 0x88, 0xB3, 0x14, 0x6A, 0xC0, 0x27,
        0x95, 0x4E, 0xA1, 0x0D, 0xE6, 0x7B, 0x29, 0xFC
    };

    private static readonly byte[] P2 =
    {
        0x31, 0x8E, 0x55, 0xA0, 0x2C, 0xF7, 0x69, 0x1B,
        0xD4, 0x08, 0x7E, 0xB2, 0x46, 0x9A, 0xC3, 0x50
    };

    private static readonly byte[] P3 =
    {
        0xA9, 0x17, 0xEC, 0x43, 0x60, 0xB8, 0x2F, 0x75,
        0x0A, 0xD1, 0x5C, 0x86, 0x3E, 0x74, 0xE0, 0x2D
    };

    // 用四段拼出的短钥 AES-ECB 解密下表，得到 32 字节因子
    private static readonly byte[] EncBlob =
    {
        0x9C, 0x5A, 0x3E, 0x11, 0x8B, 0xF0, 0x2D, 0x64,
        0xC7, 0x19, 0xA3, 0x7E, 0x45, 0xD2, 0x08, 0xBF,
        0x61, 0x3C, 0xE8, 0x2A, 0x97, 0x50, 0xD4, 0x1F,
        0x8A, 0xB6, 0x72, 0x0D, 0xF3, 0x4E, 0xC5, 0x68,
        0x12, 0x9D, 0x4B, 0xE6, 0x30, 0xAF, 0x77, 0xC1,
        0x5E, 0x04, 0xD9, 0x86, 0x2B, 0xF1, 0x63, 0xA8
    };

    private static byte[]? _cached;
    private static readonly object Gate = new();

    /// <summary>返回 32 字节软件因子（进程内缓存；调用方不得修改）。</summary>
    public static byte[] GetBytes()
    {
        if (_cached is not null)
        {
            return _cached;
        }

        lock (Gate)
        {
            if (_cached is not null)
            {
                return _cached;
            }

            var key = BuildStageKey();
            try
            {
                using var aes = Aes.Create();
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = key;
                using var dec = aes.CreateDecryptor();
                var full = dec.TransformFinalBlock(EncBlob, 0, EncBlob.Length);
                // 取前 32 字节为因子
                var factor = new byte[32];
                Array.Copy(full, factor, 32);
                CryptographicOperations.ZeroMemory(full);

                // 与产品标签再混合，避免因子单独出现在内存 dump 的固定偏移
                var label = "yuexuan-software-factor-v2"u8.ToArray();
                for (var i = 0; i < factor.Length; i++)
                {
                    factor[i] ^= label[i % label.Length];
                }

                _cached = factor;
                return _cached;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }

    private static byte[] BuildStageKey()
    {
        // 16 字节 AES 密钥 = P0^P1 ^ P2^P3 ^ 扭转常量
        var key = new byte[16];
        for (var i = 0; i < 16; i++)
        {
            key[i] = (byte)(P0[i] ^ P1[i] ^ P2[i] ^ P3[i] ^ (0xA5 + i * 3));
        }
        return key;
    }
}

/// <summary>HKDF-SHA256（RFC 5869）。</summary>
public static class Hkdf
{
    public static byte[] Derive(byte[] ikm, byte[] salt, string info, int length)
    {
        ArgumentNullException.ThrowIfNull(ikm);
        ArgumentNullException.ThrowIfNull(salt);
        ArgumentException.ThrowIfNullOrEmpty(info);

        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm,
            length,
            salt,
            System.Text.Encoding.UTF8.GetBytes(info));
    }
}
