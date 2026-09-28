namespace YuexuanCrypto.Core.Format;

/// <summary>容器格式常量。魔数避开 ZIP/7z 等常见签名。</summary>
public static class FormatConstants
{
    /// <summary>魔数 ASCII "YXENC01"（7 字节）。</summary>
    public static readonly byte[] Magic = "YXENC01"u8.ToArray();

    /// <summary>当前写入版本：v2 含 KDF 参数，解密侧兼容 v1。</summary>
    public const ushort Version = 2;
    public const ushort VersionV1 = 1;

    public const int MagicLength = 7;
    public const int SaltSize = 16;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int KeySize = 32;
    public const int MacSize = 32;
    public const int ChunkPlainSize = 1 << 20; // 1 MiB

    // ---- v2 固定头：Magic(7)+Ver(2)+Salt(16)+KdfAlgo(1)+MemKb(4)+Iters(4)+Par(1)+WrappedKey(60)+HeaderLen(4) ----
    public const int FixedHeaderSizeV2 =
        MagicLength + 2 + SaltSize + 1 + 4 + 4 + 1 + (NonceSize + KeySize + TagSize) + 4;

    // ---- v1 固定头（历史兼容）----
    public const int FixedHeaderSizeV1 =
        MagicLength + 2 + SaltSize + (NonceSize + KeySize + TagSize) + NonceSize + 4;

    public const byte KdfPbkdf2Sha256 = 1;
    public const byte KdfArgon2id = 2;

    /// <summary>v2 默认 Argon2id 参数（交互延迟与抗 GPU 之间折中）。</summary>
    public const int Argon2MemoryKb = 64 * 1024; // 64 MiB
    public const int Argon2Iterations = 3;
    public const int Argon2Parallelism = 4;

    /// <summary>v1 / 兼容路径 PBKDF2 迭代。</summary>
    public const int PasswordIterations = 600_000;

    public const string WrapInfo = "YXENC-WRAP-v1";
    public const string HeaderInfo = "YXENC-HDR-v1";
    public const string ChunkInfo = "YXENC-CHUNK-v1";
    public const string TagInfo = "YXENC-TAG-v1";
    public const string HintInfo = "YXENC-HINT-v1";

    public const string PartExtension = ".part";
    public const string ContainerExtension = ".yuexuan";
}
