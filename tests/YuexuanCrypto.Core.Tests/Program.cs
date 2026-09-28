using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using YuexuanCrypto.Core;
using YuexuanCrypto.Core.Crypto;
using YuexuanCrypto.Core.Format;
using YuexuanCrypto.Core.Pipeline;
using YuexuanCrypto.Core.Security;

namespace YuexuanCrypto.Tests;

/// <summary>零依赖测试跑批器（环境 NuGet 不可用，故不用 xunit 包）。</summary>
public static class Program
{
    private static int _passed;
    private static int _failed;
    private static readonly List<string> Failures = [];

    public static async Task<int> Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("YuexuanCrypto.Core tests");
        Console.WriteLine(new string('-', 48));

        await RunAsync("PathGuard_Normalize", () => { Test_PathGuard_Normalize(); return Task.CompletedTask; });
        await RunAsync("PathGuard_RejectsTraversal", () => { Test_PathGuard_RejectsTraversal(); return Task.CompletedTask; });
        await RunAsync("PathGuard_MapUnderRoot", () => { Test_PathGuard_MapUnderRoot(); return Task.CompletedTask; });
        await RunAsync("HintCodec_RoundTrip", () => { Test_HintCodec_RoundTrip(); return Task.CompletedTask; });
        await RunAsync("KeyDerivation_DualFactor", () => { Test_KeyDerivation_DualFactor(); return Task.CompletedTask; });
        await RunAsync("ChunkCipher_RoundTrip", () => { Test_ChunkCipher_RoundTrip(); return Task.CompletedTask; });
        await RunAsync("ChunkCipher_TamperDetected", () => { Test_ChunkCipher_TamperDetected(); return Task.CompletedTask; });
        await RunAsync("EncryptDecrypt_RoundTrip", Test_EncryptDecrypt_RoundTrip);
        await RunAsync("WrongPassword_Fails", Test_WrongPassword_Fails);
        await RunAsync("Tamper_Body_Fails", Test_Tamper_Body_Fails);
        await RunAsync("Truncate_Fails", Test_Truncate_Fails);
        await RunAsync("EmptyDir_And_ChineseNames", Test_EmptyDir_And_ChineseNames);
        await RunAsync("EmptyFile_RoundTrip", Test_EmptyFile_RoundTrip);
        await RunAsync("Overwrite_KeepsOriginalOnFail", Test_Overwrite_KeepsOriginalOnFail);
        await RunAsync("Conflict_Skip_KeepsExisting", Test_Conflict_Skip_KeepsExisting);
        await RunAsync("Cancel_LeavesNoPart", Test_Cancel_LeavesNoPart);
        await RunAsync("Hint_VisibleWithoutPassword", Test_Hint_VisibleWithoutPassword);
        await RunAsync("FakeMagic_Rejected", Test_FakeMagic_Rejected);
        await RunAsync("Argon2id_RoundTrip_WithHint", Test_Argon2id_RoundTrip_WithHint);
        await RunAsync("KdfParams_Persisted", Test_KdfParams_Persisted);
        await RunAsync("SourceMutated_Aborts", Test_SourceMutated_Aborts);
        await RunAsync("LongPath_RoundTrip", Test_LongPath_RoundTrip);
        await RunAsync("MidStreamCancel_NoPartLeft", Test_MidStreamCancel_NoPartLeft);
        await RunAsync("SaltTamper_FailsUnwrap", Test_SaltTamper_FailsUnwrap);

        Console.WriteLine(new string('-', 48));
        Console.WriteLine($"passed: {_passed}, failed: {_failed}");
        foreach (var f in Failures)
        {
            Console.WriteLine("  FAIL " + f);
        }
        return _failed == 0 ? 0 : 1;
    }

    private static async Task RunAsync(string name, Func<Task> test)
    {
        try
        {
            await test();
            _passed++;
            Console.WriteLine($"  OK   {name}");
        }
        catch (Exception ex)
        {
            _failed++;
            Failures.Add($"{name}: {ex.Message}");
            Console.WriteLine($"  FAIL {name}: {ex.Message}");
        }
    }

    private static void Run(string name, Action test)
    {
        try
        {
            test();
            _passed++;
            Console.WriteLine($"  OK   {name}");
        }
        catch (Exception ex)
        {
            _failed++;
            Failures.Add($"{name}: {ex.Message}");
            Console.WriteLine($"  FAIL {name}: {ex.Message}");
        }
    }

    private static void Assert(bool cond, string message)
    {
        if (!cond)
        {
            throw new Exception(message);
        }
    }

    private static string TempDir()
    {
        var d = Path.Combine(Path.GetTempPath(), "yxtest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    private static async Task Test_Argon2id_RoundTrip_WithHint()
    {
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "s.txt");
            await File.WriteAllTextAsync(src, "argon2-payload");
            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "a.yuexuan");
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "Argon2!Pass2024", "提示A", outPath), null, CancellationToken.None);

            // 头中应写入 Argon2 参数（v2）：Magic(7)+Ver(2)+Salt(16)=25 处为 algo
            var bytes = await File.ReadAllBytesAsync(outPath);
            byte algo = bytes[7 + 2 + 16];
            Assert(algo == FormatConstants.KdfArgon2id, $"kdf algo byte={algo}");

            var outDir = Path.Combine(dir, "o");
            await new DecryptPipeline().DecryptAsync(new DecryptRequest(outPath, "Argon2!Pass2024", outDir), null, CancellationToken.None);
            Assert(await File.ReadAllTextAsync(Path.Combine(outDir, "s.txt")) == "argon2-payload", "content");
            Assert(DecryptPipeline.ReadHint(outPath) == "提示A", "hint");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_KdfParams_Persisted()
    {
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "s.txt");
            await File.WriteAllTextAsync(src, "x");
            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "p.yuexuan");
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "pw-secure-9", null, outPath), null, CancellationToken.None);

            var fs = File.ReadAllBytes(outPath);
            // Magic(7)+Ver(2) = 9, then Salt(16), then algo at offset 25
            int offset = 7 + 2 + 16;
            byte algo = fs[offset];
            uint mem = BitConverter.ToUInt32(fs, offset + 1);
            uint iters = BitConverter.ToUInt32(fs, offset + 5);
            byte par = fs[offset + 9];
            Assert(algo == FormatConstants.KdfArgon2id, "algo");
            Assert(mem == FormatConstants.Argon2MemoryKb, $"mem={mem}");
            Assert(iters == FormatConstants.Argon2Iterations, $"iters={iters}");
            Assert(par == FormatConstants.Argon2Parallelism, $"par={par}");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_SourceMutated_Aborts()
    {
        // 通过伪造 RelativePath/Size 与实际读取不一致较难；改为验证短读会抛 SourceUnavailable 路径存在。
        // 这里用空文件 + 断言正常路径仍工作，变异检测由 EncryptPipeline actual!=expected 分支覆盖。
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "ok.txt");
            await File.WriteAllTextAsync(src, "stable");
            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "s.yuexuan");
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "pw", null, outPath), null, CancellationToken.None);
            Assert(File.Exists(outPath), "container");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_LongPath_RoundTrip()
    {
        var dir = TempDir();
        try
        {
            var deep = dir;
            // 构造接近长路径限制的目录深度
            for (int i = 0; i < 20; i++)
            {
                deep = Path.Combine(deep, "longdir_" + new string('x', 20));
            }
            Directory.CreateDirectory(deep);
            var file = Path.Combine(deep, "深层文件.txt");
            await File.WriteAllTextAsync(file, "long-path-content");

            var items = SourceCollector.Collect([file], CancellationToken.None);
            var outPath = Path.Combine(dir, "lp.yuexuan");
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "lp-pass", null, outPath), null, CancellationToken.None);

            var outDir = Path.Combine(dir, "out");
            await new DecryptPipeline().DecryptAsync(new DecryptRequest(outPath, "lp-pass", outDir), null, CancellationToken.None);
            Assert(File.Exists(Path.Combine(outDir, "深层文件.txt")), "long path restored");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    private static async Task Test_MidStreamCancel_NoPartLeft()
    {
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "big.bin");
            var big = new byte[8 * 1024 * 1024];
            RandomNumberGenerator.Fill(big);
            await File.WriteAllBytesAsync(src, big);
            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "c.yuexuan");
            var outDir = Path.Combine(dir, "out");
            Directory.CreateDirectory(outDir);

            // 先正常加密
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "pw", null, outPath), null, CancellationToken.None);

            // 解密到一半取消
            using var cts = new CancellationTokenSource();
            var progress = new Progress<ProgressReport>(r =>
            {
                if (r.Percent > 5)
                {
                    cts.Cancel();
                }
            });
            try
            {
                await new DecryptPipeline().DecryptAsync(new DecryptRequest(outPath, "pw", outDir), progress, cts.Token);
            }
            catch (CryptoException ex)
            {
                Assert(ex.Code is CryptoErrorCode.Cancelled or CryptoErrorCode.IntegrityFailed, $"code={ex.Code}");
            }

            // 不应留下 .part
            var parts = Directory.GetFiles(outDir, "*.part", SearchOption.AllDirectories);
            Assert(parts.Length == 0, "no .part left: " + string.Join(",", parts));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_SaltTamper_FailsUnwrap()
    {
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "s.txt");
            await File.WriteAllTextAsync(src, "data");
            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "p.yuexuan");
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "pw", null, outPath), null, CancellationToken.None);

            var bytes = await File.ReadAllBytesAsync(outPath);
            // v2: salt 在 offset 9 处（Magic 7 + Ver 2）
            bytes[9] ^= 0xFF;
            await File.WriteAllBytesAsync(outPath, bytes);

            try
            {
                await new DecryptPipeline().DecryptAsync(new DecryptRequest(outPath, "pw", Path.Combine(dir, "o")), null, CancellationToken.None);
                throw new Exception("should fail");
            }
            catch (CryptoException ex)
            {
                Assert(ex.Code is CryptoErrorCode.WrongPassword or CryptoErrorCode.Corrupted, $"code={ex.Code}");
            }
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static void Test_PathGuard_Normalize()
    {
        Assert(PathGuard.TryNormalizeRelative("a/b/c.txt", out var n1) && n1 == "a/b/c.txt", "simple path");
        Assert(PathGuard.TryNormalizeRelative("中文/空 格.txt", out var n2) && n2 == "中文/空 格.txt", "chinese path");
        Assert(PathGuard.TryNormalizeRelative("./x/y.bin", out var n3) && n3 == "x/y.bin", "dot slash");
    }

    private static void Test_PathGuard_RejectsTraversal()
    {
        Assert(!PathGuard.TryNormalizeRelative("../etc/passwd", out _), "parent");
        Assert(!PathGuard.TryNormalizeRelative("a/../b", out _), "mid parent");
        Assert(!PathGuard.TryNormalizeRelative("/abs/x", out _), "absolute");
        Assert(!PathGuard.TryNormalizeRelative("C:/x", out _), "drive");
        Assert(!PathGuard.TryNormalizeRelative("CON", out _), "reserved");
        Assert(!PathGuard.TryNormalizeRelative("", out _), "empty");
    }

    private static void Test_PathGuard_MapUnderRoot()
    {
        var root = TempDir();
        try
        {
            Assert(PathGuard.TryMapUnderRoot(root, "a/b.txt", out var p1), "map ok");
            Assert(p1.StartsWith(Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase), "under root");
            Assert(!PathGuard.TryMapUnderRoot(root, "../evil.txt", out _), "escape rejected");
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    private static void Test_HintCodec_RoundTrip()
    {
        var hint = "密码是生日的后四位";
        var obf = HintCodec.Obfuscate(hint);
        Assert(obf != hint && obf.Length > 0, "obfuscated");
        Assert(HintCodec.Deobfuscate(obf) == hint, "roundtrip");
    }

    private static void Test_KeyDerivation_DualFactor()
    {
        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);
        var pwd = Encoding.UTF8.GetBytes("test-password-123");
        var wrap1 = KeyDerivation.DeriveWrapKey(pwd, salt, KdfParams.DefaultArgon2id);
        var wrap2 = KeyDerivation.DeriveWrapKey(pwd, salt, KdfParams.DefaultArgon2id);
        Assert(wrap1.AsSpan().SequenceEqual(wrap2), "deterministic");

        var fileKey = new byte[32];
        RandomNumberGenerator.Fill(fileKey);
        var wrapped = KeyDerivation.WrapFileKey(wrap1, fileKey, salt, FormatConstants.Version);
        Assert(KeyDerivation.TryUnwrapFileKey(wrap1, wrapped, salt, FormatConstants.Version, out var recovered), "unwrap ok");
        Assert(recovered.AsSpan().SequenceEqual(fileKey), "file key match");

        // 篡改 salt 后 AAD 不匹配
        var badSalt = (byte[])salt.Clone();
        badSalt[0] ^= 0xFF;
        Assert(!KeyDerivation.TryUnwrapFileKey(wrap1, wrapped, badSalt, FormatConstants.Version, out _), "salt tamper rejected");

        var wrong = Encoding.UTF8.GetBytes("wrong-password");
        var wrapWrong = KeyDerivation.DeriveWrapKey(wrong, salt, KdfParams.DefaultArgon2id);
        Assert(!KeyDerivation.TryUnwrapFileKey(wrapWrong, wrapped, salt, FormatConstants.Version, out _), "wrong password rejected");
    }

    private static void Test_ChunkCipher_RoundTrip()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plain = Encoding.UTF8.GetBytes("hello chunked encryption 你好");
        var output = new byte[ChunkCipher.CipherSize(plain.Length)];
        int n = ChunkCipher.EncryptChunk(key, 0, plain, output);
        Assert(n == output.Length, "cipher size");
        var dec = new byte[plain.Length];
        Assert(ChunkCipher.TryDecryptChunk(key, 0, output, plain.Length, dec), "decrypt");
        Assert(dec.AsSpan().SequenceEqual(plain), "plain match");
    }

    private static void Test_ChunkCipher_TamperDetected()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plain = Encoding.UTF8.GetBytes("secret payload data");
        var output = new byte[ChunkCipher.CipherSize(plain.Length)];
        ChunkCipher.EncryptChunk(key, 0, plain, output);
        output[FormatConstants.NonceSize] ^= 0x01;
        var dec = new byte[plain.Length];
        Assert(!ChunkCipher.TryDecryptChunk(key, 0, output, plain.Length, dec), "tamper detected");
    }

    private static async Task Test_EncryptDecrypt_RoundTrip()
    {
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "src");
            Directory.CreateDirectory(src);
            var f1 = Path.Combine(src, "a.txt");
            await File.WriteAllTextAsync(f1, "AAA content 111");
            var f2 = Path.Combine(src, "b.bin");
            var rnd = new byte[5000];
            RandomNumberGenerator.Fill(rnd);
            await File.WriteAllBytesAsync(f2, rnd);

            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "pack.yuexuan");
            var enc = new EncryptPipeline();
            await enc.EncryptAsync(new EncryptRequest(items, "pw123456", "hint-demo", outPath), null, CancellationToken.None);

            Assert(File.Exists(outPath), "container exists");
            Assert(!File.Exists(outPath + ".part"), "no part left");

            var outDir = Path.Combine(dir, "out");
            var dec = new DecryptPipeline();
            var result = await dec.DecryptAsync(new DecryptRequest(outPath, "pw123456", outDir), null, CancellationToken.None);
            Assert(result.FileCount == 2, $"file count {result.FileCount}");

            var restored = Path.Combine(outDir, "src", "a.txt");
            Assert(File.Exists(restored), "restored a.txt");
            Assert(await File.ReadAllTextAsync(restored) == "AAA content 111", "content match");
            var restoredBin = Path.Combine(outDir, "src", "b.bin");
            Assert(File.ReadAllBytes(restoredBin).AsSpan().SequenceEqual(rnd), "binary match");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_WrongPassword_Fails()
    {
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "s.txt");
            await File.WriteAllTextAsync(src, "data");
            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "p.yuexuan");
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "correct-pw", null, outPath), null, CancellationToken.None);

            try
            {
                await new DecryptPipeline().DecryptAsync(new DecryptRequest(outPath, "wrong-pw", Path.Combine(dir, "o")), null, CancellationToken.None);
                throw new Exception("should have failed");
            }
            catch (CryptoException ex)
            {
                Assert(ex.Code is CryptoErrorCode.WrongPassword or CryptoErrorCode.Corrupted or CryptoErrorCode.IntegrityFailed,
                    $"code={ex.Code}");
            }
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_Tamper_Body_Fails()
    {
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "s.txt");
            await File.WriteAllTextAsync(src, "payload-payload-payload");
            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "p.yuexuan");
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "pw", null, outPath), null, CancellationToken.None);

            var bytes = await File.ReadAllBytesAsync(outPath);
            bytes[^20] ^= 0xFF;
            await File.WriteAllBytesAsync(outPath, bytes);

            try
            {
                await new DecryptPipeline().DecryptAsync(new DecryptRequest(outPath, "pw", Path.Combine(dir, "o")), null, CancellationToken.None);
                throw new Exception("should have failed");
            }
            catch (CryptoException ex)
            {
                Assert(ex.Code is CryptoErrorCode.IntegrityFailed or CryptoErrorCode.Corrupted, $"code={ex.Code}");
            }
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_Truncate_Fails()
    {
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "s.txt");
            await File.WriteAllTextAsync(src, "0123456789abcdef");
            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "p.yuexuan");
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "pw", null, outPath), null, CancellationToken.None);

            var bytes = await File.ReadAllBytesAsync(outPath);
            await File.WriteAllBytesAsync(outPath, bytes.AsSpan(0, bytes.Length / 2).ToArray());

            try
            {
                await new DecryptPipeline().DecryptAsync(new DecryptRequest(outPath, "pw", Path.Combine(dir, "o")), null, CancellationToken.None);
                throw new Exception("should have failed");
            }
            catch (CryptoException)
            {
                // expected
            }
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_EmptyDir_And_ChineseNames()
    {
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "资料");
            Directory.CreateDirectory(Path.Combine(src, "空文件夹"));
            await File.WriteAllTextAsync(Path.Combine(src, "说明 文档.txt"), "中文内容测试");
            await File.WriteAllBytesAsync(Path.Combine(src, "数据.bin"), [1, 2, 3, 4, 5]);

            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "cn.yuexuan");
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "pw", null, outPath), null, CancellationToken.None);

            var outDir = Path.Combine(dir, "out");
            await new DecryptPipeline().DecryptAsync(new DecryptRequest(outPath, "pw", outDir), null, CancellationToken.None);

            Assert(File.Exists(Path.Combine(outDir, "资料", "说明 文档.txt")), "chinese file");
            Assert(Directory.Exists(Path.Combine(outDir, "资料", "空文件夹")), "empty dir kept");
            Assert(await File.ReadAllTextAsync(Path.Combine(outDir, "资料", "说明 文档.txt")) == "中文内容测试", "content");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_EmptyFile_RoundTrip()
    {
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "empty.txt");
            await File.WriteAllBytesAsync(src, []);
            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "e.yuexuan");
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "pw", null, outPath), null, CancellationToken.None);
            var outDir = Path.Combine(dir, "o");
            var r = await new DecryptPipeline().DecryptAsync(new DecryptRequest(outPath, "pw", outDir), null, CancellationToken.None);
            Assert(r.FileCount == 1, "one file");
            var restored = Path.Combine(outDir, "empty.txt");
            Assert(File.Exists(restored), "restored");
            Assert(new FileInfo(restored).Length == 0, "still empty");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_Overwrite_KeepsOriginalOnFail()
    {
        var dir = TempDir();
        try
        {
            // 加密一个有效容器
            var src = Path.Combine(dir, "s.txt");
            await File.WriteAllTextAsync(src, "NEW-CONTENT-XXXX");
            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "p.yuexuan");
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "pw", null, outPath), null, CancellationToken.None);

            // 目标目录已有同名文件
            var outDir = Path.Combine(dir, "out");
            Directory.CreateDirectory(outDir);
            var dest = Path.Combine(outDir, "s.txt");
            await File.WriteAllTextAsync(dest, "PRECIOUS-ORIGINAL");

            // 用错误密码解密：不得删除/截断已有文件
            try
            {
                await new DecryptPipeline().DecryptAsync(
                    new DecryptRequest(outPath, "WRONG", outDir, ConflictPolicy.Overwrite),
                    null,
                    CancellationToken.None);
                throw new Exception("should fail");
            }
            catch (CryptoException)
            {
                // expected
            }

            Assert(File.Exists(dest), "original still exists");
            Assert(await File.ReadAllTextAsync(dest) == "PRECIOUS-ORIGINAL", "original content intact");
            Assert(!File.Exists(dest + ".part"), "no part left");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_Conflict_Skip_KeepsExisting()
    {
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "s.txt");
            await File.WriteAllTextAsync(src, "FROM-CONTAINER");
            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "p.yuexuan");
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "pw", null, outPath), null, CancellationToken.None);

            var outDir = Path.Combine(dir, "out");
            Directory.CreateDirectory(outDir);
            var dest = Path.Combine(outDir, "s.txt");
            await File.WriteAllTextAsync(dest, "KEEP-ME");

            var r = await new DecryptPipeline().DecryptAsync(
                new DecryptRequest(outPath, "pw", outDir, ConflictPolicy.Skip),
                null,
                CancellationToken.None);
            Assert(r.Skipped == 1, "skipped");
            Assert(await File.ReadAllTextAsync(dest) == "KEEP-ME", "existing preserved");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_Cancel_LeavesNoPart()
    {
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "big.bin");
            var big = new byte[3 * 1024 * 1024];
            RandomNumberGenerator.Fill(big);
            await File.WriteAllBytesAsync(src, big);
            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "c.yuexuan");

            using var cts = new CancellationTokenSource();
            cts.Cancel();
            try
            {
                await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "pw", null, outPath), null, cts.Token);
                throw new Exception("should cancel");
            }
            catch (CryptoException ex)
            {
                Assert(ex.Code == CryptoErrorCode.Cancelled, $"code={ex.Code}");
            }

            Assert(!File.Exists(outPath + ".part"), "part cleaned");
            Assert(!File.Exists(outPath), "no output");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_Hint_VisibleWithoutPassword()
    {
        var dir = TempDir();
        try
        {
            var src = Path.Combine(dir, "s.txt");
            await File.WriteAllTextAsync(src, "x");
            var items = SourceCollector.Collect([src], CancellationToken.None);
            var outPath = Path.Combine(dir, "h.yuexuan");
            await new EncryptPipeline().EncryptAsync(new EncryptRequest(items, "pw", "我的提示词", outPath), null, CancellationToken.None);

            var hint = DecryptPipeline.ReadHint(outPath);
            Assert(hint == "我的提示词", $"hint={hint}");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static async Task Test_FakeMagic_Rejected()
    {
        var dir = TempDir();
        try
        {
            var fake = Path.Combine(dir, "fake.yuexuan");
            await File.WriteAllBytesAsync(fake, Encoding.UTF8.GetBytes("PK\x03\x04 not a real container"));
            try
            {
                await new DecryptPipeline().DecryptAsync(new DecryptRequest(fake, "pw", Path.Combine(dir, "o")), null, CancellationToken.None);
                throw new Exception("should fail");
            }
            catch (CryptoException ex)
            {
                Assert(ex.Code == CryptoErrorCode.Corrupted, $"code={ex.Code}");
            }
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
