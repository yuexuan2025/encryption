using System.Security.Cryptography;
using YuexuanCrypto.Core.Format;

namespace YuexuanCrypto.Core.Crypto;

/// <summary>分块 AES-256-GCM：内存占用与文件大小无关，适合数十 GB 级文件。</summary>
public static class ChunkCipher
{
    /// <summary>
    /// 加密一块明文。输出布局：nonce(12) || ct || tag(16)。
    /// aad 使用块索引，防止块重排。
    /// </summary>
    public static int EncryptChunk(
        ReadOnlySpan<byte> chunkKey,
        ulong chunkIndex,
        ReadOnlySpan<byte> plain,
        Span<byte> output)
    {
        int need = FormatConstants.NonceSize + plain.Length + FormatConstants.TagSize;
        if (output.Length < need)
        {
            throw new ArgumentException($"输出缓冲不足，需要 {need} 字节。", nameof(output));
        }

        var nonce = output[..FormatConstants.NonceSize];
        // 4 字节随机 + 8 字节大端块索引，保证同密钥下 nonce 唯一
        RandomNumberGenerator.Fill(nonce[..4]);
        WriteUInt64BigEndian(nonce[4..], chunkIndex);

        var ct = output.Slice(FormatConstants.NonceSize, plain.Length);
        var tag = output.Slice(FormatConstants.NonceSize + plain.Length, FormatConstants.TagSize);

        Span<byte> aad = stackalloc byte[8];
        WriteUInt64BigEndian(aad, chunkIndex);

        using var gcm = new AesGcm(chunkKey, FormatConstants.TagSize);
        gcm.Encrypt(nonce, plain, ct, tag, aad);
        return need;
    }

    /// <summary>解密一块；认证失败返回 false。</summary>
    public static bool TryDecryptChunk(
        ReadOnlySpan<byte> chunkKey,
        ulong chunkIndex,
        ReadOnlySpan<byte> input,
        int plainLength,
        Span<byte> plainOutput)
    {
        int need = FormatConstants.NonceSize + plainLength + FormatConstants.TagSize;
        if (input.Length < need || plainOutput.Length < plainLength)
        {
            return false;
        }

        var nonce = input[..FormatConstants.NonceSize];
        var ct = input.Slice(FormatConstants.NonceSize, plainLength);
        var tag = input.Slice(FormatConstants.NonceSize + plainLength, FormatConstants.TagSize);

        Span<byte> aad = stackalloc byte[8];
        WriteUInt64BigEndian(aad, chunkIndex);

        try
        {
            using var gcm = new AesGcm(chunkKey, FormatConstants.TagSize);
            gcm.Decrypt(nonce, ct, tag, plainOutput[..plainLength], aad);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public static int CipherSize(int plainLength) =>
        FormatConstants.NonceSize + plainLength + FormatConstants.TagSize;

    private static void WriteUInt64BigEndian(Span<byte> dest, ulong value)
    {
        dest[0] = (byte)(value >> 56);
        dest[1] = (byte)(value >> 48);
        dest[2] = (byte)(value >> 40);
        dest[3] = (byte)(value >> 32);
        dest[4] = (byte)(value >> 24);
        dest[5] = (byte)(value >> 16);
        dest[6] = (byte)(value >> 8);
        dest[7] = (byte)value;
    }
}

/// <summary>流式 HMAC-SHA256，用于容器截断/拼接检测。</summary>
public sealed class StreamMac : IDisposable
{
    private readonly IncrementalHash _hash;

    public StreamMac(byte[] tagKey)
    {
        _hash = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, tagKey);
    }

    public void Append(ReadOnlySpan<byte> data) => _hash.AppendData(data);

    /// <summary>取出最终 MAC 并重置内部状态，不可重复调用。</summary>
    public byte[] GetFinal() => _hash.GetHashAndReset();

    public void Dispose() => _hash.Dispose();
}
