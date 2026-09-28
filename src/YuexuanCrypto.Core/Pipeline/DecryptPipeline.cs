using System.Diagnostics;
using System.Security.Cryptography;
using YuexuanCrypto.Core.Crypto;
using YuexuanCrypto.Core.Format;
using YuexuanCrypto.Core.Security;

namespace YuexuanCrypto.Core.Pipeline;

/// <summary>解密管道：校验完整性、路径防护、冲突策略、失败清理。</summary>
public sealed class DecryptPipeline
{
    public async Task<DecryptResult> DecryptAsync(
        DecryptRequest request,
        IProgress<ProgressReport>? progress,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (string.IsNullOrEmpty(request.Password))
        {
            throw new CryptoException(CryptoErrorCode.InvalidArgument, "密码不能为空。");
        }
        if (string.IsNullOrEmpty(request.ContainerPath) || !File.Exists(request.ContainerPath))
        {
            throw new CryptoException(CryptoErrorCode.IoError, "找不到加密容器文件。");
        }

        var containerPath = Path.GetFullPath(request.ContainerPath);
        var outputRoot = Path.GetFullPath(request.OutputDirectory);
        Directory.CreateDirectory(outputRoot);

        var sw = Stopwatch.StartNew();
        long bytesDone = 0;
        long bytesTotal = 0;
        int filesDone = 0;
        int filesTotal = 0;
        int skipped = 0;
        int renamed = 0;
        var stage = OperationStage.Preparing;

        void Report(string? current = null)
        {
            progress?.Report(new ProgressReport(
                bytesDone,
                bytesTotal,
                filesDone,
                filesTotal,
                stage,
                sw.Elapsed.TotalSeconds <= 0 ? 0 : bytesDone / sw.Elapsed.TotalSeconds,
                sw.Elapsed,
                bytesTotal > 0 && bytesDone > 0
                    ? TimeSpan.FromSeconds(sw.Elapsed.TotalSeconds * (bytesTotal - bytesDone) / Math.Max(1, bytesDone))
                    : null,
                current));
        }

        KeyDerivation.DerivedKeys? keys = null;
        StreamMac? mac = null;
        var tempOutputs = new List<string>();
        var pendingCommits = new List<(string Part, string Dest)>();
        var createdDirs = new List<string>();

        try
        {
            Report();
            await using var fs = EncryptPipeline.OpenReadLongPath(containerPath);

            // 固定头
            var magic = await ReadExactAsync(fs, FormatConstants.MagicLength, ct).ConfigureAwait(false);
            if (magic is null || !magic.AsSpan().SequenceEqual(FormatConstants.Magic))
            {
                throw new CryptoException(CryptoErrorCode.Corrupted, "文件不是有效的 .yuexuan 加密容器。");
            }

            var verBytes = await ReadExactAsync(fs, 2, ct).ConfigureAwait(false);
            if (verBytes is null)
            {
                throw new CryptoException(CryptoErrorCode.Corrupted, "容器头不完整。");
            }
            ushort version = BitConverter.ToUInt16(verBytes);
            if (version is not (FormatConstants.Version or FormatConstants.VersionV1))
            {
                throw new CryptoException(CryptoErrorCode.Corrupted, $"不支持的容器版本：{version}。");
            }

            var salt = await ReadExactAsync(fs, FormatConstants.SaltSize, ct).ConfigureAwait(false)
                ?? throw new CryptoException(CryptoErrorCode.Corrupted, "容器头不完整。");

            KdfParams kdf;
            if (version == FormatConstants.VersionV1)
            {
                kdf = KdfParams.LegacyPbkdf2;
            }
            else
            {
                var algo = await ReadExactAsync(fs, 1, ct).ConfigureAwait(false)
                    ?? throw new CryptoException(CryptoErrorCode.Corrupted, "容器头不完整。");
                var mem = await ReadExactAsync(fs, 4, ct).ConfigureAwait(false)
                    ?? throw new CryptoException(CryptoErrorCode.Corrupted, "容器头不完整。");
                var iters = await ReadExactAsync(fs, 4, ct).ConfigureAwait(false)
                    ?? throw new CryptoException(CryptoErrorCode.Corrupted, "容器头不完整。");
                var par = await ReadExactAsync(fs, 1, ct).ConfigureAwait(false)
                    ?? throw new CryptoException(CryptoErrorCode.Corrupted, "容器头不完整。");
                kdf = new KdfParams(
                    algo[0],
                    (int)BitConverter.ToUInt32(mem),
                    (int)BitConverter.ToUInt32(iters),
                    par[0]);
            }

            var wrappedKey = await ReadExactAsync(fs, FormatConstants.NonceSize + FormatConstants.KeySize + FormatConstants.TagSize, ct).ConfigureAwait(false)
                ?? throw new CryptoException(CryptoErrorCode.Corrupted, "容器头不完整。");

            // v1 有未使用的 headerNonce，需跳过以保持兼容
            if (version == FormatConstants.VersionV1)
            {
                _ = await ReadExactAsync(fs, FormatConstants.NonceSize, ct).ConfigureAwait(false)
                    ?? throw new CryptoException(CryptoErrorCode.Corrupted, "容器头不完整。");
            }

            var headerLenBytes = await ReadExactAsync(fs, 4, ct).ConfigureAwait(false)
                ?? throw new CryptoException(CryptoErrorCode.Corrupted, "容器头不完整。");
            uint headerLen = BitConverter.ToUInt32(headerLenBytes);
            if (headerLen > 64 * 1024 * 1024)
            {
                throw new CryptoException(CryptoErrorCode.Corrupted, "容器头过大，文件可能已损坏。");
            }
            var headerBlob = await ReadExactAsync(fs, (int)headerLen, ct).ConfigureAwait(false)
                ?? throw new CryptoException(CryptoErrorCode.Corrupted, "容器头不完整。");

            var hintLenBytes = await ReadExactAsync(fs, 4, ct).ConfigureAwait(false)
                ?? throw new CryptoException(CryptoErrorCode.Corrupted, "容器头不完整。");
            uint hintLen = BitConverter.ToUInt32(hintLenBytes);
            if (hintLen > 4096)
            {
                throw new CryptoException(CryptoErrorCode.Corrupted, "容器头异常。");
            }
            var hintBlob = await ReadExactAsync(fs, (int)hintLen, ct).ConfigureAwait(false)
                ?? throw new CryptoException(CryptoErrorCode.Corrupted, "容器头不完整。");

            // 双因子：密码 + 软件因子
            var passwordBytes = SensitiveBuffer.FromUtf8(request.Password);
            byte[] wrapKey;
            try
            {
                wrapKey = KeyDerivation.DeriveWrapKey(passwordBytes, salt, kdf);
            }
            finally
            {
                SensitiveBuffer.Zero(passwordBytes);
            }

            if (!KeyDerivation.TryUnwrapFileKey(wrapKey, wrappedKey, salt, version, out var fileKey))
            {
                SensitiveBuffer.Zero(wrapKey);
                throw new CryptoException(CryptoErrorCode.WrongPassword, "密码错误，或此文件需要使用配套软件解密。");
            }

            keys = KeyDerivation.Expand(wrapKey, fileKey, salt);

            // headerBlob 自身布局为 nonce||ct||tag（见 HeaderCipher）
            Manifest? manifest;
            try
            {
                manifest = HeaderCipher.TryDecryptManifest(headerBlob, keys.HeaderKey);
            }
            catch
            {
                manifest = null;
            }
            if (manifest is null)
            {
                throw new CryptoException(CryptoErrorCode.Corrupted, "容器头已损坏。");
            }

            filesTotal = manifest.Entries.Count(e => e.Type == EntryType.File);
            bytesTotal = manifest.Entries.Where(e => e.Type == EntryType.File).Sum(e => e.Size);

            mac = new StreamMac(keys.TagKey);
            mac.Append(wrappedKey);
            mac.Append(headerBlob);
            mac.Append(hintBlob);

            stage = OperationStage.Decrypting;
            ulong chunkIndex = 0;
            var cipherBuf = new byte[ChunkCipher.CipherSize(FormatConstants.ChunkPlainSize)];
            var plainBuf = new byte[FormatConstants.ChunkPlainSize];

            // 先建目录
            foreach (var entry in manifest.Entries)
            {
                ct.ThrowIfCancellationRequested();
                if (entry.Type != EntryType.Directory)
                {
                    continue;
                }
                if (!PathGuard.TryMapUnderRoot(outputRoot, entry.Path, out var dirPath))
                {
                    throw new CryptoException(CryptoErrorCode.PathUnsafe, $"容器包含不安全路径：{entry.Path}");
                }
                if (!Directory.Exists(dirPath))
                {
                    Directory.CreateDirectory(dirPath);
                    createdDirs.Add(dirPath);
                }
            }

            foreach (var entry in manifest.Entries)
            {
                ct.ThrowIfCancellationRequested();
                if (entry.Type != EntryType.File)
                {
                    continue;
                }

                if (!PathGuard.TryMapUnderRoot(outputRoot, entry.Path, out var destPath))
                {
                    throw new CryptoException(CryptoErrorCode.PathUnsafe, $"容器包含不安全路径：{entry.Path}");
                }

                // 冲突处理（支持批量「全部应用」：由 ConflictResolver 维护 sticky 策略）
                ConflictPolicy effective = request.ConflictPolicy;
                if (File.Exists(destPath))
                {
                    if (effective == ConflictPolicy.Ask && request.ConflictResolver is not null)
                    {
                        effective = request.ConflictResolver(entry.Path, destPath);
                    }
                    if (effective == ConflictPolicy.Ask)
                    {
                        throw new CryptoException(CryptoErrorCode.InvalidArgument, $"目标已存在：{entry.Path}");
                    }
                    if (effective == ConflictPolicy.Skip)
                    {
                        // 仍须读过该文件的分块以保持流对齐
                        chunkIndex = await SkipFileChunksAsync(fs, keys.ChunkKey, entry.Size, chunkIndex, mac!, ct).ConfigureAwait(false);
                        filesDone++;
                        skipped++;
                        bytesDone += entry.Size;
                        Report(entry.Path);
                        continue;
                    }
                    if (effective == ConflictPolicy.Rename)
                    {
                        destPath = MakeUniquePath(destPath);
                        renamed++;
                    }
                }

                Report(entry.Path);
                // 先写 .part，全部校验通过后再提交，失败/取消只删 .part
                var partPath = destPath + FormatConstants.PartExtension;
                tempOutputs.Add(partPath);
                pendingCommits.Add((partPath, destPath));
                await using (var output = EncryptPipeline.OpenWriteLongPath(partPath))
                {
                    long remaining = entry.Size;
                    while (remaining > 0)
                    {
                        ct.ThrowIfCancellationRequested();
                        int plainLen = (int)Math.Min(FormatConstants.ChunkPlainSize, remaining);
                        int cipherLen = ChunkCipher.CipherSize(plainLen);
                        var block = await ReadExactAsync(fs, cipherLen, ct).ConfigureAwait(false)
                            ?? throw new CryptoException(CryptoErrorCode.Corrupted, $"数据块不完整：{entry.Path}");
                        mac.Append(block);

                        if (!ChunkCipher.TryDecryptChunk(keys.ChunkKey, chunkIndex, block, plainLen, plainBuf))
                        {
                            throw new CryptoException(CryptoErrorCode.IntegrityFailed, "数据校验失败：文件已损坏或被篡改。");
                        }

                        await output.WriteAsync(plainBuf.AsMemory(0, plainLen), ct).ConfigureAwait(false);
                        chunkIndex++;
                        remaining -= plainLen;
                        bytesDone += plainLen;
                        Report(entry.Path);
                    }

                    await output.FlushAsync(ct).ConfigureAwait(false);
                }

                filesDone++;
            }

            // Footer 校验
            stage = OperationStage.Finalizing;
            Report();
            var footer = await ReadExactAsync(fs, 8 + FormatConstants.MacSize, ct).ConfigureAwait(false)
                ?? throw new CryptoException(CryptoErrorCode.Corrupted, "容器尾不完整。");
            ulong totalChunks = BitConverter.ToUInt64(footer, 0);
            var expectedMac = footer.AsSpan(8, FormatConstants.MacSize).ToArray();
            var actualMac = mac.GetFinal();
            if (totalChunks != chunkIndex || !CryptographicOperations.FixedTimeEquals(expectedMac, actualMac))
            {
                foreach (var p in tempOutputs)
                {
                    TryDelete(p);
                }
                throw new CryptoException(CryptoErrorCode.IntegrityFailed, "容器完整性校验失败：文件已损坏或被篡改。");
            }

            // 多余数据视为损坏
            var extra = await fs.ReadAsync(new byte[1], ct).ConfigureAwait(false);
            if (extra > 0)
            {
                foreach (var p in tempOutputs)
                {
                    TryDelete(p);
                }
                throw new CryptoException(CryptoErrorCode.Corrupted, "容器尾部存在多余数据。");
            }

            // 校验全部通过后才原子提交，避免半截提取破坏目标目录
            foreach (var (part, dest) in pendingCommits)
            {
                CommitPart(part, dest);
            }

            stage = OperationStage.Completed;
            Report();
            return new DecryptResult(filesDone, manifest.Entries.Count(e => e.Type == EntryType.Directory), skipped, renamed, bytesDone);
        }
        catch (OperationCanceledException)
        {
            CleanupOutputs(tempOutputs, createdDirs);
            throw new CryptoException(CryptoErrorCode.Cancelled, "操作已取消。");
        }
        catch (CryptoException)
        {
            CleanupOutputs(tempOutputs, createdDirs);
            throw;
        }
        catch (Exception ex)
        {
            CleanupOutputs(tempOutputs, createdDirs);
            throw new CryptoException(CryptoErrorCode.IoError, $"解密失败：{ex.Message}", ex);
        }
        finally
        {
            keys?.Zero();
            mac?.Dispose();
        }
    }

    private static void CleanupOutputs(List<string> parts, List<string> dirs)
    {
        foreach (var p in parts)
        {
            TryDelete(p);
        }
        // 仅删除本次新建的空目录
        foreach (var d in dirs.OrderByDescending(d => d.Length))
        {
            try
            {
                if (Directory.Exists(d) && !Directory.EnumerateFileSystemEntries(d).Any())
                {
                    Directory.Delete(d);
                }
            }
            catch
            {
                // 忽略清理失败
            }
        }
    }

    /// <summary>读取容器中的提示词（无需密码，软件因子混淆）。兼容 v1/v2 头布局。</summary>
    public static string? ReadHint(string containerPath)
    {
        try
        {
            using var fs = EncryptPipeline.OpenReadLongPath(containerPath);
            var magic = new byte[FormatConstants.MagicLength];
            if (fs.Read(magic, 0, magic.Length) != magic.Length || !magic.AsSpan().SequenceEqual(FormatConstants.Magic))
            {
                return null;
            }

            var verBytes = new byte[2];
            if (fs.Read(verBytes, 0, 2) != 2)
            {
                return null;
            }
            ushort version = BitConverter.ToUInt16(verBytes);

            // 跳过 salt
            fs.Position += FormatConstants.SaltSize;

            if (version == FormatConstants.VersionV1)
            {
                // v1: wrappedKey(60) + headerNonce(12) + headerLen(4)
                fs.Position += FormatConstants.NonceSize + FormatConstants.KeySize + FormatConstants.TagSize
                               + FormatConstants.NonceSize;
            }
            else
            {
                // v2: kdf(1+4+4+1) + wrappedKey(60) + headerLen(4)
                fs.Position += 1 + 4 + 4 + 1
                               + FormatConstants.NonceSize + FormatConstants.KeySize + FormatConstants.TagSize;
            }

            var lenBuf = new byte[4];
            if (fs.Read(lenBuf, 0, 4) != 4)
            {
                return null;
            }
            uint headerLen = BitConverter.ToUInt32(lenBuf);
            if (headerLen > 64 * 1024 * 1024)
            {
                return null;
            }
            fs.Position += headerLen;

            var hintLenBuf = new byte[4];
            if (fs.Read(hintLenBuf, 0, 4) != 4)
            {
                return null;
            }
            uint hintLen = BitConverter.ToUInt32(hintLenBuf);
            if (hintLen > 4096)
            {
                return null;
            }
            var hintBlob = new byte[hintLen];
            if (hintLen > 0 && fs.Read(hintBlob, 0, (int)hintLen) != (int)hintLen)
            {
                return null;
            }
            return HintStore.Decode(hintBlob);
        }
        catch
        {
            return null;
        }
    }

    private static async Task<ulong> SkipFileChunksAsync(
        Stream fs,
        byte[] chunkKey,
        long size,
        ulong chunkIndex,
        StreamMac mac,
        CancellationToken ct)
    {
        long remaining = size;
        var plainBuf = new byte[FormatConstants.ChunkPlainSize];
        while (remaining > 0)
        {
            ct.ThrowIfCancellationRequested();
            int plainLen = (int)Math.Min(FormatConstants.ChunkPlainSize, remaining);
            int cipherLen = ChunkCipher.CipherSize(plainLen);
            var block = await ReadExactAsync(fs, cipherLen, ct).ConfigureAwait(false)
                ?? throw new CryptoException(CryptoErrorCode.Corrupted, "数据块不完整。");
            mac.Append(block);
            if (!ChunkCipher.TryDecryptChunk(chunkKey, chunkIndex, block, plainLen, plainBuf))
            {
                throw new CryptoException(CryptoErrorCode.IntegrityFailed, "数据校验失败：文件已损坏或被篡改。");
            }
            chunkIndex++;
            remaining -= plainLen;
        }
        return chunkIndex;
    }

    private static string MakeUniquePath(string path)
    {
        var dir = Path.GetDirectoryName(path) ?? "";
        var name = Path.GetFileNameWithoutExtension(path);
        var ext = Path.GetExtension(path);
        for (int i = 1; ; i++)
        {
            var candidate = Path.Combine(dir, $"{name} ({i}){ext}");
            if (!File.Exists(candidate))
            {
                return candidate;
            }
        }
    }

    private static void CommitPart(string partPath, string destPath)
    {
        File.Move(partPath, destPath, overwrite: true);
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // 忽略清理失败
        }
    }

    private static async Task<byte[]?> ReadExactAsync(Stream stream, int count, CancellationToken ct)
    {
        var buf = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int n = await stream.ReadAsync(buf.AsMemory(offset, count - offset), ct).ConfigureAwait(false);
            if (n <= 0)
            {
                return null;
            }
            offset += n;
        }
        return buf;
    }
}
