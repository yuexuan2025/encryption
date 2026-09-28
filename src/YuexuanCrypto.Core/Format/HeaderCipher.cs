using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using YuexuanCrypto.Core.Crypto;
using YuexuanCrypto.Core.Format;

namespace YuexuanCrypto.Core.Format;

public enum EntryType
{
    File = 0,
    Directory = 1
}

public sealed class ManifestEntry
{
    [JsonPropertyName("t")]
    public EntryType Type { get; set; }

    [JsonPropertyName("p")]
    public string Path { get; set; } = "";

    [JsonPropertyName("s")]
    public long Size { get; set; }
}

public sealed class Manifest
{
    [JsonPropertyName("v")]
    public int Version { get; set; } = 1;

    /// <summary>兼容字段；正式提示存于 HintStore 旁路。</summary>
    [JsonPropertyName("hint")]
    public string? HintObfuscated { get; set; }

    [JsonPropertyName("entries")]
    public List<ManifestEntry> Entries { get; set; } = [];
}

/// <summary>加密头读写（AES-256-GCM）。</summary>
public static class HeaderCipher
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static byte[] EncryptManifest(Manifest manifest, ReadOnlySpan<byte> headerKey)
    {
        var plain = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);
        try
        {
            var nonce = new byte[FormatConstants.NonceSize];
            RandomNumberGenerator.Fill(nonce);
            var output = new byte[FormatConstants.NonceSize + plain.Length + FormatConstants.TagSize];
            nonce.CopyTo(output, 0);

            using var gcm = new AesGcm(headerKey, FormatConstants.TagSize);
            gcm.Encrypt(
                nonce,
                plain,
                output.AsSpan(FormatConstants.NonceSize, plain.Length),
                output.AsSpan(FormatConstants.NonceSize + plain.Length, FormatConstants.TagSize),
                FormatConstants.Magic);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public static Manifest? TryDecryptManifest(ReadOnlySpan<byte> blob, ReadOnlySpan<byte> headerKey)
    {
        if (blob.Length < FormatConstants.NonceSize + FormatConstants.TagSize)
        {
            return null;
        }

        var nonce = blob[..FormatConstants.NonceSize];
        int plainLen = blob.Length - FormatConstants.NonceSize - FormatConstants.TagSize;
        var ct = blob.Slice(FormatConstants.NonceSize, plainLen);
        var tag = blob.Slice(FormatConstants.NonceSize + plainLen, FormatConstants.TagSize);
        var plain = new byte[plainLen];
        try
        {
            using var gcm = new AesGcm(headerKey, FormatConstants.TagSize);
            gcm.Decrypt(nonce, ct, tag, plain, FormatConstants.Magic);
            return JsonSerializer.Deserialize<Manifest>(plain, JsonOptions);
        }
        catch (Exception e) when (e is CryptographicException or JsonException)
        {
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }
}

/// <summary>密码提示轻度混淆：XOR(HKDF(software_factor, HINT))，非明文可扫。</summary>
public static class HintCodec
{
    public static string Obfuscate(string hint)
    {
        if (string.IsNullOrEmpty(hint))
        {
            return "";
        }
        var key = Hkdf.Derive(SoftwareFactor.GetBytes(), "hint-salt-yuexuan-v1"u8.ToArray(), FormatConstants.HintInfo, 32);
        var data = Encoding.UTF8.GetBytes(hint);
        for (var i = 0; i < data.Length; i++)
        {
            data[i] ^= key[i % key.Length];
        }
        CryptographicOperations.ZeroMemory(key);
        return Convert.ToBase64String(data);
    }

    public static string Deobfuscate(string obfuscated)
    {
        if (string.IsNullOrEmpty(obfuscated))
        {
            return "";
        }
        byte[] data;
        try
        {
            data = Convert.FromBase64String(obfuscated);
        }
        catch (FormatException)
        {
            return "";
        }
        var key = Hkdf.Derive(SoftwareFactor.GetBytes(), "hint-salt-yuexuan-v1"u8.ToArray(), FormatConstants.HintInfo, 32);
        for (var i = 0; i < data.Length; i++)
        {
            data[i] ^= key[i % key.Length];
        }
        CryptographicOperations.ZeroMemory(key);
        return Encoding.UTF8.GetString(data);
    }
}
