using System.Security.Cryptography;
using Isopoh.Cryptography.Argon2;
using YuexuanCrypto.Core.Format;
using YuexuanCrypto.Core.Security;

namespace YuexuanCrypto.Core.Crypto;

/// <summary>KDF 参数：随容器存储，保证未来改参仍能解密旧文件。</summary>
public sealed record KdfParams(
    byte Algorithm,
    int MemoryKb,
    int Iterations,
    int Parallelism)
{
    public static KdfParams DefaultArgon2id => new(
        FormatConstants.KdfArgon2id,
        FormatConstants.Argon2MemoryKb,
        FormatConstants.Argon2Iterations,
        FormatConstants.Argon2Parallelism);

    public static KdfParams LegacyPbkdf2 => new(
        FormatConstants.KdfPbkdf2Sha256,
        0,
        FormatConstants.PasswordIterations,
        1);
}

/// <summary>由用户密码 + 软件因子派生密钥材料。</summary>
public static class KeyDerivation
{
    public sealed record DerivedKeys(
        byte[] WrapKey,
        byte[] HeaderKey,
        byte[] ChunkKey,
        byte[] TagKey,
        byte[] FileKey)
    {
        public void Zero()
        {
            CryptographicOperations.ZeroMemory(WrapKey);
            CryptographicOperations.ZeroMemory(HeaderKey);
            CryptographicOperations.ZeroMemory(ChunkKey);
            CryptographicOperations.ZeroMemory(TagKey);
            CryptographicOperations.ZeroMemory(FileKey);
        }
    }

    /// <summary>从密码与 salt 派生 wrap key（双因子：密码 + 软件内置因子）。</summary>
    public static byte[] DeriveWrapKey(
        ReadOnlySpan<byte> passwordBytes,
        ReadOnlySpan<byte> salt,
        KdfParams? kdf = null)
    {
        if (passwordBytes.IsEmpty)
        {
            throw new ArgumentException("密码不能为空。", nameof(passwordBytes));
        }
        if (salt.Length != FormatConstants.SaltSize)
        {
            throw new ArgumentException("Salt 长度不正确。", nameof(salt));
        }

        kdf ??= KdfParams.DefaultArgon2id;
        var pwdKey = new byte[FormatConstants.KeySize];
        try
        {
            DerivePasswordKey(passwordBytes, salt, kdf, pwdKey);

            var software = SoftwareFactor.GetBytes();
            var ikm = new byte[pwdKey.Length + software.Length];
            try
            {
                pwdKey.CopyTo(ikm, 0);
                software.CopyTo(ikm, pwdKey.Length);
                return Hkdf.Derive(ikm, salt.ToArray(), FormatConstants.WrapInfo, FormatConstants.KeySize);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ikm);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwdKey);
        }
    }

    private static void DerivePasswordKey(
        ReadOnlySpan<byte> passwordBytes,
        ReadOnlySpan<byte> salt,
        KdfParams kdf,
        Span<byte> destination)
    {
        if (kdf.Algorithm == FormatConstants.KdfPbkdf2Sha256)
        {
            Rfc2898DeriveBytes.Pbkdf2(
                passwordBytes,
                salt,
                destination,
                Math.Max(1, kdf.Iterations),
                HashAlgorithmName.SHA256);
            return;
        }

        if (kdf.Algorithm == FormatConstants.KdfArgon2id)
        {
            var pwd = passwordBytes.ToArray();
            var saltArr = salt.ToArray();
            try
            {
                var config = new Argon2Config
                {
                    Type = Argon2Type.HybridAddressing,
                    TimeCost = Math.Max(1, kdf.Iterations),
                    MemoryCost = Math.Max(8, kdf.MemoryKb),
                    Threads = Math.Max(1, kdf.Parallelism),
                    Password = pwd,
                    Salt = saltArr,
                    HashLength = destination.Length
                };
                using var argon2 = new Argon2(config);
                using var hash = argon2.Hash();
                if (hash.Buffer is null || hash.Buffer.Length < destination.Length)
                {
                    throw new CryptographicException("Argon2id 输出长度异常。");
                }
                for (int i = 0; i < destination.Length; i++)
                {
                    destination[i] = hash.Buffer[i];
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pwd);
                CryptographicOperations.ZeroMemory(saltArr);
            }
            return;
        }

        throw new NotSupportedException($"不支持的 KDF：{kdf.Algorithm}");
    }

    /// <summary>生成随机 file key 并派生各用途子密钥。</summary>
    public static DerivedKeys CreateForEncryption(
        ReadOnlySpan<byte> passwordBytes,
        ReadOnlySpan<byte> salt,
        KdfParams? kdf = null)
    {
        var wrapKey = DeriveWrapKey(passwordBytes, salt, kdf);
        var fileKey = new byte[FormatConstants.KeySize];
        RandomNumberGenerator.Fill(fileKey);
        return Expand(wrapKey, fileKey, salt);
    }

    /// <summary>解密时用已还原的 file key 扩展子密钥。</summary>
    public static DerivedKeys Expand(byte[] wrapKey, byte[] fileKey, ReadOnlySpan<byte> salt)
    {
        var saltArr = salt.ToArray();
        try
        {
            var headerKey = Hkdf.Derive(fileKey, saltArr, FormatConstants.HeaderInfo, FormatConstants.KeySize);
            var chunkKey = Hkdf.Derive(fileKey, saltArr, FormatConstants.ChunkInfo, FormatConstants.KeySize);
            var tagKey = Hkdf.Derive(fileKey, saltArr, FormatConstants.TagInfo, FormatConstants.KeySize);
            return new DerivedKeys(wrapKey, headerKey, chunkKey, tagKey, fileKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(saltArr);
        }
    }

    /// <summary>构造 file-key 包装 AAD：绑定魔数 + 版本 + salt，防止头字段被偷换。</summary>
    public static byte[] BuildWrapAad(ReadOnlySpan<byte> salt, ushort version)
    {
        // Magic || Version(LE) || Salt
        var aad = new byte[FormatConstants.MagicLength + 2 + salt.Length];
        FormatConstants.Magic.CopyTo(aad, 0);
        aad[FormatConstants.MagicLength] = (byte)version;
        aad[FormatConstants.MagicLength + 1] = (byte)(version >> 8);
        salt.CopyTo(aad.AsSpan(FormatConstants.MagicLength + 2));
        return aad;
    }

    /// <summary>AES-256-GCM 包装/解包 file key。</summary>
    public static byte[] WrapFileKey(byte[] wrapKey, byte[] fileKey, ReadOnlySpan<byte> salt, ushort version)
    {
        var nonce = new byte[FormatConstants.NonceSize];
        RandomNumberGenerator.Fill(nonce);
        var output = new byte[FormatConstants.NonceSize + FormatConstants.KeySize + FormatConstants.TagSize];
        nonce.CopyTo(output, 0);
        var aad = BuildWrapAad(salt, version);
        try
        {
            using var gcm = new AesGcm(wrapKey, FormatConstants.TagSize);
            gcm.Encrypt(
                nonce,
                fileKey,
                output.AsSpan(FormatConstants.NonceSize, FormatConstants.KeySize),
                output.AsSpan(FormatConstants.NonceSize + FormatConstants.KeySize, FormatConstants.TagSize),
                aad);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    /// <summary>解包 file key；认证失败视为密码错误或容器被破坏。</summary>
    public static bool TryUnwrapFileKey(
        ReadOnlySpan<byte> wrapKey,
        ReadOnlySpan<byte> wrapped,
        ReadOnlySpan<byte> salt,
        ushort version,
        out byte[] fileKey)
    {
        fileKey = [];
        if (wrapped.Length != FormatConstants.NonceSize + FormatConstants.KeySize + FormatConstants.TagSize)
        {
            return false;
        }

        var nonce = wrapped[..FormatConstants.NonceSize];
        var ct = wrapped.Slice(FormatConstants.NonceSize, FormatConstants.KeySize);
        var tag = wrapped.Slice(FormatConstants.NonceSize + FormatConstants.KeySize, FormatConstants.TagSize);
        var plain = new byte[FormatConstants.KeySize];
        var aad = BuildWrapAad(salt, version);
        try
        {
            using var gcm = new AesGcm(wrapKey, FormatConstants.TagSize);
            gcm.Decrypt(nonce, ct, tag, plain, aad);
            fileKey = plain;
            return true;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plain);
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }
    }
}
