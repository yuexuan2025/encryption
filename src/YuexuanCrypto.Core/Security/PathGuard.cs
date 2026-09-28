namespace YuexuanCrypto.Core.Security;

/// <summary>路径防护：拒绝 zip-slip、绝对路径、盘符、保留设备名。</summary>
public static class PathGuard
{
    private static readonly HashSet<string> ReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    /// <summary>规范化容器内相对路径；失败返回 false。</summary>
    public static bool TryNormalizeRelative(string input, out string normalized)
    {
        normalized = "";
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var s = input.Replace('\\', '/').Trim();
        while (s.StartsWith("./", StringComparison.Ordinal))
        {
            s = s[2..];
        }

        if (s.StartsWith('/') || s.StartsWith("//", StringComparison.Ordinal))
        {
            return false;
        }
        if (s.Contains(':') || s.Contains('\0'))
        {
            return false;
        }

        var parts = new List<string>();
        foreach (var raw in s.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            var part = raw.Trim();
            if (part is "." or "..")
            {
                return false;
            }
            if (part.EndsWith(' ') || part.EndsWith('.'))
            {
                // Windows 会剥离尾部空格/点，这里直接拒绝以保证往返一致
                return false;
            }
            var nameNoExt = part.Contains('.') ? part[..part.IndexOf('.')] : part;
            if (ReservedNames.Contains(nameNoExt))
            {
                return false;
            }
            parts.Add(part);
        }

        if (parts.Count == 0)
        {
            return false;
        }

        normalized = string.Join('/', parts);
        return true;
    }

    /// <summary>将相对路径安全映射到目标根目录下；拒绝逃逸与重解析点（junction/symlink）。</summary>
    public static bool TryMapUnderRoot(string rootDir, string relativePath, out string fullPath)
    {
        fullPath = "";
        if (!TryNormalizeRelative(relativePath, out var rel))
        {
            return false;
        }

        var rootFull = Path.GetFullPath(rootDir);
        if (!rootFull.EndsWith(Path.DirectorySeparatorChar))
        {
            rootFull += Path.DirectorySeparatorChar;
        }

        var combined = Path.GetFullPath(Path.Combine(rootFull, rel.Replace('/', Path.DirectorySeparatorChar)));
        if (!combined.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // 拒绝路径上任何已存在的重解析点（junction/symlink），防 zip-slip 变种
        if (ContainsReparsePoint(rootFull, combined))
        {
            return false;
        }

        fullPath = combined;
        return true;
    }

    private static bool ContainsReparsePoint(string rootFull, string fullPath)
    {
        try
        {
            var rootInfo = new DirectoryInfo(rootFull.TrimEnd(Path.DirectorySeparatorChar));
            if (IsReparse(rootInfo))
            {
                return true;
            }

            // 从根到目标的每一级父目录
            var current = Path.GetDirectoryName(fullPath);
            while (!string.IsNullOrEmpty(current)
                   && current.Length >= rootFull.TrimEnd(Path.DirectorySeparatorChar).Length
                   && current.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
            {
                var dir = new DirectoryInfo(current);
                if (dir.Exists && IsReparse(dir))
                {
                    return true;
                }
                var parent = Path.GetDirectoryName(current);
                if (string.IsNullOrEmpty(parent) || parent == current)
                {
                    break;
                }
                current = parent;
            }

            // 目标本身若是已存在的重解析文件/目录也拒绝
            if (File.Exists(fullPath))
            {
                var attrs = File.GetAttributes(fullPath);
                if ((attrs & FileAttributes.ReparsePoint) != 0)
                {
                    return true;
                }
            }
            else if (Directory.Exists(fullPath))
            {
                if (IsReparse(new DirectoryInfo(fullPath)))
                {
                    return true;
                }
            }

            return false;
        }
        catch
        {
            // 无法判断时按不安全处理
            return true;
        }
    }

    private static bool IsReparse(FileSystemInfo info) =>
        info.Exists && (info.Attributes & FileAttributes.ReparsePoint) != 0;
}

/// <summary>敏感字节缓冲：用后清零。</summary>
public static class SensitiveBuffer
{
    public static byte[] FromUtf8(string text)
    {
        return System.Text.Encoding.UTF8.GetBytes(text);
    }

    public static void Zero(byte[]? buffer)
    {
        if (buffer is { Length: > 0 })
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer);
        }
    }
}
