using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using YuexuanCrypto.Core.Crypto;
using YuexuanCrypto.Core.Format;
using YuexuanCrypto.Core.Security;

namespace YuexuanCrypto.Core.Pipeline;

public enum OperationStage
{
    Preparing,
    ReadingSource,
    Encrypting,
    Writing,
    Finalizing,
    Decrypting,
    Extracting,
    Completed,
    Cancelled
}

public sealed record ProgressReport(
    long BytesDone,
    long BytesTotal,
    int FilesDone,
    int FilesTotal,
    OperationStage Stage,
    double BytesPerSecond,
    TimeSpan Elapsed,
    TimeSpan? Eta,
    string? CurrentItem = null)
{
    public double Percent => BytesTotal <= 0 ? 0 : Math.Clamp(100.0 * BytesDone / BytesTotal, 0, 100);
}

public enum CryptoErrorCode
{
    None = 0,
    WrongPassword,
    Corrupted,
    IntegrityFailed,
    IoError,
    Cancelled,
    PathUnsafe,
    DiskSpace,
    SourceUnavailable,
    InvalidArgument,
    Unknown
}

public sealed class CryptoException : Exception
{
    public CryptoErrorCode Code { get; }

    public CryptoException(CryptoErrorCode code, string message, Exception? inner = null)
        : base(message, inner)
    {
        Code = code;
    }
}

public enum ConflictPolicy
{
    Ask,
    Overwrite,
    Skip,
    Rename
}

public sealed record SourceItem(string FullPath, string RelativePath, bool IsDirectory);

public sealed record EncryptRequest(
    IReadOnlyList<SourceItem> Items,
    string Password,
    string? Hint,
    string OutputPath);

public sealed record DecryptRequest(
    string ContainerPath,
    string Password,
    string OutputDirectory,
    ConflictPolicy ConflictPolicy = ConflictPolicy.Ask,
    Func<string, string, ConflictPolicy>? ConflictResolver = null);

public sealed record EncryptResult(string OutputPath, int FileCount, int DirectoryCount, long TotalBytes);

public sealed record DecryptResult(int FileCount, int DirectoryCount, int Skipped, int Renamed, long TotalBytes);

/// <summary>采集目录/文件列表，规范化相对路径。</summary>
public static class SourceCollector
{
    public static List<SourceItem> Collect(IEnumerable<string> paths, CancellationToken ct)
    {
        var items = new List<SourceItem>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var path in paths)
        {
            ct.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            var full = Path.GetFullPath(path);
            if (File.Exists(full))
            {
                AddFile(items, seen, full, Path.GetFileName(full));
            }
            else if (Directory.Exists(full))
            {
                var rootName = new DirectoryInfo(full).Name;
                foreach (var dir in Directory.EnumerateDirectories(full, "*", new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    IgnoreInaccessible = false,
                    AttributesToSkip = 0
                }))
                {
                    ct.ThrowIfCancellationRequested();
                    var rel = Path.GetRelativePath(full, dir).Replace('\\', '/');
                    AddDir(items, seen, rootName + "/" + rel);
                }

                foreach (var file in Directory.EnumerateFiles(full, "*", new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    IgnoreInaccessible = false,
                    AttributesToSkip = 0
                }))
                {
                    ct.ThrowIfCancellationRequested();
                    var rel = Path.GetRelativePath(full, file).Replace('\\', '/');
                    AddFile(items, seen, file, rootName + "/" + rel);
                }

                // 空目录也保留
                if (!Directory.EnumerateFileSystemEntries(full, "*", new EnumerationOptions
                    {
                        RecurseSubdirectories = true,
                        AttributesToSkip = 0
                    }).Any())
                {
                    AddDir(items, seen, rootName);
                }
            }
            else
            {
                throw new CryptoException(CryptoErrorCode.SourceUnavailable, $"找不到路径：{path}");
            }
        }

        return items;
    }

    private static void AddFile(List<SourceItem> items, HashSet<string> seen, string fullPath, string relative)
    {
        if (!PathGuard.TryNormalizeRelative(relative, out var norm))
        {
            throw new CryptoException(CryptoErrorCode.PathUnsafe, $"不安全的路径：{relative}");
        }
        if (seen.Add("F:" + norm))
        {
            items.Add(new SourceItem(fullPath, norm, false));
        }
    }

    private static void AddDir(List<SourceItem> items, HashSet<string> seen, string relative)
    {
        if (!PathGuard.TryNormalizeRelative(relative, out var norm))
        {
            throw new CryptoException(CryptoErrorCode.PathUnsafe, $"不安全的路径：{relative}");
        }
        if (seen.Add("D:" + norm))
        {
            items.Add(new SourceItem("", norm, true));
        }
    }
}

/// <summary>加密管道：流式分块，失败/取消删除 .part，绝不改动源文件。</summary>
public sealed class EncryptPipeline
{
    public async Task<EncryptResult> EncryptAsync(
        EncryptRequest request,
        IProgress<ProgressReport>? progress,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Items.Count == 0)
        {
            throw new CryptoException(CryptoErrorCode.InvalidArgument, "没有可加密的项目。");
        }
        if (string.IsNullOrEmpty(request.Password))
        {
            throw new CryptoException(CryptoErrorCode.InvalidArgument, "密码不能为空。");
        }

        var outputFull = Path.GetFullPath(request.OutputPath);
        if (!outputFull.EndsWith(FormatConstants.ContainerExtension, StringComparison.OrdinalIgnoreCase))
        {
            outputFull += FormatConstants.ContainerExtension;
        }
        var partPath = outputFull + FormatConstants.PartExtension;

        var outDir = Path.GetDirectoryName(outputFull);
        if (!string.IsNullOrEmpty(outDir))
        {
            Directory.CreateDirectory(outDir);
        }

        long totalBytes = 0;
        var sizeByPath = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var item in request.Items)
        {
            if (!item.IsDirectory)
            {
                long len = new FileInfo(item.FullPath).Length;
                sizeByPath[item.RelativePath] = len;
                totalBytes += len;
            }
        }

        // 磁盘空间预检：容器约等于源数据 + 少量头开销
        try
        {
            var drive = new DriveInfo(Path.GetPathRoot(outputFull) ?? "C:\\");
            long need = totalBytes + (1L << 20); // 1MiB 余量
            if (drive.IsReady && drive.AvailableFreeSpace < need)
            {
                throw new CryptoException(
                    CryptoErrorCode.DiskSpace,
                    $"磁盘空间不足：需要约 {need / 1024.0 / 1024:F1} MB，可用 {drive.AvailableFreeSpace / 1024.0 / 1024:F1} MB。");
            }
        }
        catch (CryptoException)
        {
            throw;
        }
        catch
        {
            // 无法检测时继续，写入失败会报 IoError
        }

        var sw = Stopwatch.StartNew();
        long bytesDone = 0;
        int filesDone = 0;
        var stage = OperationStage.Preparing;

        void Report(string? current = null)
        {
            progress?.Report(new ProgressReport(
                bytesDone,
                totalBytes,
                filesDone,
                request.Items.Count(i => !i.IsDirectory),
                stage,
                sw.Elapsed.TotalSeconds <= 0 ? 0 : bytesDone / sw.Elapsed.TotalSeconds,
                sw.Elapsed,
                totalBytes > 0 && bytesDone > 0
                    ? TimeSpan.FromSeconds(sw.Elapsed.TotalSeconds * (totalBytes - bytesDone) / Math.Max(1, bytesDone))
                    : null,
                current));
        }

        FileStream? fs = null;
        KeyDerivation.DerivedKeys? keys = null;
        StreamMac? mac = null;

        try
        {
            Report();
            fs = new FileStream(partPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16, useAsync: true);

            var salt = new byte[FormatConstants.SaltSize];
            RandomNumberGenerator.Fill(salt);
            var kdf = KdfParams.DefaultArgon2id;
            var passwordBytes = SensitiveBuffer.FromUtf8(request.Password);
            try
            {
                keys = KeyDerivation.CreateForEncryption(passwordBytes, salt, kdf);
            }
            finally
            {
                SensitiveBuffer.Zero(passwordBytes);
            }

            var manifest = new Manifest
            {
                HintObfuscated = string.IsNullOrWhiteSpace(request.Hint) ? null : HintCodec.Obfuscate(request.Hint!)
            };

            foreach (var item in request.Items)
            {
                ct.ThrowIfCancellationRequested();
                manifest.Entries.Add(new ManifestEntry
                {
                    Type = item.IsDirectory ? EntryType.Directory : EntryType.File,
                    Path = item.RelativePath,
                    Size = item.IsDirectory ? 0 : new FileInfo(item.FullPath).Length
                });
            }

            var headerBlob = HeaderCipher.EncryptManifest(manifest, keys.HeaderKey);
            var wrappedKey = KeyDerivation.WrapFileKey(keys.WrapKey, keys.FileKey, salt, FormatConstants.Version);
            var hintBlob = HintStore.Encode(request.Hint);

            // v2 固定头（含 KDF 参数，便于未来改参仍可解密）
            await WriteAsync(fs, FormatConstants.Magic, ct).ConfigureAwait(false);
            await WriteU16Async(fs, FormatConstants.Version, ct).ConfigureAwait(false);
            await WriteAsync(fs, salt, ct).ConfigureAwait(false);
            fs.WriteByte(kdf.Algorithm);
            await WriteU32Async(fs, (uint)kdf.MemoryKb, ct).ConfigureAwait(false);
            await WriteU32Async(fs, (uint)kdf.Iterations, ct).ConfigureAwait(false);
            fs.WriteByte((byte)kdf.Parallelism);
            await WriteAsync(fs, wrappedKey, ct).ConfigureAwait(false);
            await WriteU32Async(fs, (uint)headerBlob.Length, ct).ConfigureAwait(false);
            await WriteAsync(fs, headerBlob, ct).ConfigureAwait(false);
            await WriteU32Async(fs, (uint)hintBlob.Length, ct).ConfigureAwait(false);
            await WriteAsync(fs, hintBlob, ct).ConfigureAwait(false);

            mac = new StreamMac(keys.TagKey);
            mac.Append(wrappedKey);
            mac.Append(headerBlob);
            mac.Append(hintBlob);

            stage = OperationStage.Encrypting;
            ulong chunkIndex = 0;
            var cipherBuf = new byte[ChunkCipher.CipherSize(FormatConstants.ChunkPlainSize)];
            var plainBuf = new byte[FormatConstants.ChunkPlainSize];

            foreach (var item in request.Items)
            {
                ct.ThrowIfCancellationRequested();
                if (item.IsDirectory)
                {
                    continue;
                }

                Report(item.RelativePath);
                await using var input = await OpenReadWithRetryAsync(item.FullPath, ct).ConfigureAwait(false);
                long expected = sizeByPath.TryGetValue(item.RelativePath, out var sz) ? sz : new FileInfo(item.FullPath).Length;
                long actual = 0;
                while (true)
                {
                    ct.ThrowIfCancellationRequested();
                    int read = await input.ReadAsync(plainBuf.AsMemory(0, plainBuf.Length), ct).ConfigureAwait(false);
                    if (read <= 0)
                    {
                        break;
                    }

                    int written = ChunkCipher.EncryptChunk(keys.ChunkKey, chunkIndex, plainBuf.AsSpan(0, read), cipherBuf);
                    await WriteAsync(fs, cipherBuf.AsMemory(0, written), ct).ConfigureAwait(false);
                    mac.Append(cipherBuf.AsSpan(0, written));
                    chunkIndex++;
                    bytesDone += read;
                    actual += read;
                    Report(item.RelativePath);
                }

                if (actual != expected)
                {
                    throw new CryptoException(
                        CryptoErrorCode.SourceUnavailable,
                        $"文件在加密过程中被修改，已中止：{item.RelativePath}");
                }

                filesDone++;
                Report(item.RelativePath);
            }

            stage = OperationStage.Finalizing;
            Report();

            // Footer: total_chunks + stream_mac（MAC 覆盖 wrappedKey|header|hint|chunks；KDF 参数经 AAD/salt 绑定）
            var footer = new byte[8 + FormatConstants.MacSize];
            BitConverter.TryWriteBytes(footer.AsSpan(0, 8), chunkIndex);
            var digest = mac.GetFinal();
            digest.CopyTo(footer, 8);
            await WriteAsync(fs, footer, ct).ConfigureAwait(false);

            await fs.FlushAsync(ct).ConfigureAwait(false);
            await fs.DisposeAsync().ConfigureAwait(false);
            fs = null;

            // 原子替换：File.Move(overwrite) 避免 delete+move 窗口
            File.Move(partPath, outputFull, overwrite: true);

            stage = OperationStage.Completed;
            Report();
            return new EncryptResult(
                outputFull,
                request.Items.Count(i => !i.IsDirectory),
                request.Items.Count(i => i.IsDirectory),
                totalBytes);
        }
        catch (OperationCanceledException)
        {
            TryDelete(fs, partPath);
            throw new CryptoException(CryptoErrorCode.Cancelled, "操作已取消。");
        }
        catch (CryptoException)
        {
            TryDelete(fs, partPath);
            throw;
        }
        catch (Exception ex)
        {
            TryDelete(fs, partPath);
            if (ex is IOException io && (io.HResult & 0xFFFF) is 32 or 33)
            {
                throw new CryptoException(
                    CryptoErrorCode.SourceUnavailable,
                    $"文件正被其他程序占用，无法读取：{ex.Message}",
                    ex);
            }
            throw new CryptoException(CryptoErrorCode.IoError, $"加密失败：{ex.Message}", ex);
        }
        finally
        {
            keys?.Zero();
            mac?.Dispose();
            if (fs is not null)
            {
                await fs.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private static void TryDelete(FileStream? fs, string partPath)
    {
        try
        {
            fs?.Dispose();
            if (File.Exists(partPath))
            {
                File.Delete(partPath);
            }
        }
        catch
        {
            // 尽力清理，不掩盖原始错误
        }
    }

    internal static FileStream OpenReadLongPath(string path)
    {
        var full = Path.GetFullPath(path);
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !full.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            full = @"\\?\" + full;
        }
        return new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, useAsync: true);
    }

    /// <summary>短暂自动重试被占用的文件；仍失败则抛 SourceUnavailable。</summary>
    internal static async Task<FileStream> OpenReadWithRetryAsync(string path, CancellationToken ct)
    {
        const int maxAttempts = 5;
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                return OpenReadLongPath(path);
            }
            catch (IOException ex) when (attempt < maxAttempts && (ex.HResult & 0xFFFF) is 32 or 33)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(150 * attempt), ct).ConfigureAwait(false);
            }
            catch (IOException ex) when ((ex.HResult & 0xFFFF) is 32 or 33)
            {
                throw new CryptoException(
                    CryptoErrorCode.SourceUnavailable,
                    $"文件正被其他程序占用，请关闭后重试：{Path.GetFileName(path)}",
                    ex);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new CryptoException(
                    CryptoErrorCode.SourceUnavailable,
                    $"没有读取权限：{Path.GetFileName(path)}",
                    ex);
            }
        }
    }

    internal static FileStream OpenWriteLongPath(string path)
    {
        var full = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !full.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            full = @"\\?\" + full;
        }
        return new FileStream(full, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16, useAsync: true);
    }

    private static async Task WriteAsync(FileStream fs, byte[] data, CancellationToken ct) =>
        await fs.WriteAsync(data, ct).ConfigureAwait(false);

    private static async Task WriteAsync(FileStream fs, ReadOnlyMemory<byte> data, CancellationToken ct) =>
        await fs.WriteAsync(data, ct).ConfigureAwait(false);

    private static Task WriteAsync(Stream s, ReadOnlyMemory<byte> data, CancellationToken ct) =>
        s.WriteAsync(data, ct).AsTask();

    private static async Task WriteU16Async(FileStream fs, ushort value, CancellationToken ct)
    {
        var buf = BitConverter.GetBytes(value);
        await fs.WriteAsync(buf, ct).ConfigureAwait(false);
    }

    private static async Task WriteU32Async(FileStream fs, uint value, CancellationToken ct)
    {
        var buf = BitConverter.GetBytes(value);
        await fs.WriteAsync(buf, ct).ConfigureAwait(false);
    }
}
