using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using YuexuanCrypto.Core.Pipeline;

namespace YuexuanCrypto.App.ViewModels;

public enum AppMode
{
    Encrypt,
    Decrypt
}

public sealed class MainViewModel : INotifyPropertyChanged
{
    private CancellationTokenSource? _cts;

    public ObservableCollection<FileItemViewModel> Items { get; } = [];

    private string _itemsSummary = "尚未添加项目";
    public string ItemsSummary
    {
        get => _itemsSummary;
        private set { _itemsSummary = value; OnPropertyChanged(); }
    }

    private void RefreshItemsSummary()
    {
        if (Items.Count == 0)
        {
            ItemsSummary = "尚未添加项目";
            return;
        }
        int files = 0, dirs = 0;
        long bytes = 0;
        foreach (var i in Items)
        {
            if (i.IsDirectory)
            {
                dirs++;
            }
            else
            {
                files++;
            }
            bytes += i.SizeBytes;
        }
        ItemsSummary = $"{Items.Count} 项（文件 {files} / 文件夹 {dirs}），约 {FormatSize(bytes)}";
        OnPropertyChanged(nameof(ItemsCountText));
    }

    public string ItemsCountText => Items.Count == 0 ? "" : $"共 {Items.Count} 项";

    private AppMode _mode = AppMode.Encrypt;
    public AppMode Mode
    {
        get => _mode;
        set
        {
            if (_mode == value)
            {
                return;
            }
            _mode = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsEncryptMode));
            OnPropertyChanged(nameof(IsDecryptMode));
            OnPropertyChanged(nameof(PrimaryActionText));
        }
    }

    public bool IsEncryptMode
    {
        get => _mode == AppMode.Encrypt;
        set
        {
            if (value)
            {
                Mode = AppMode.Encrypt;
            }
        }
    }

    public bool IsDecryptMode
    {
        get => _mode == AppMode.Decrypt;
        set
        {
            if (value)
            {
                Mode = AppMode.Decrypt;
            }
        }
    }

    public string PrimaryActionText => _mode == AppMode.Encrypt ? "开始加密" : "开始解密";

    private string _password = "";
    public string Password
    {
        get => _password;
        set { _password = value; OnPropertyChanged(); UpdateStrength(); }
    }

    private bool _showPassword;
    public bool ShowPassword
    {
        get => _showPassword;
        set
        {
            if (_showPassword == value)
            {
                return;
            }
            _showPassword = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(ShowPasswordGlyph));
            PasswordVisibilityChanged?.Invoke();
        }
    }

    public string ShowPasswordGlyph => _showPassword ? "🙈" : "👁";

    /// <summary>由视图同步 PasswordBox 可见性。</summary>
    public event Action? PasswordVisibilityChanged;

    private string _passwordConfirm = "";
    public string PasswordConfirm
    {
        get => _passwordConfirm;
        set { _passwordConfirm = value; OnPropertyChanged(); }
    }

    private string _hint = "";
    public string Hint
    {
        get => _hint;
        set { _hint = value; OnPropertyChanged(); }
    }

    private string _outputPath = "";
    public string OutputPath
    {
        get => _outputPath;
        set { _outputPath = value; OnPropertyChanged(); }
    }

    private string _targetFolder = "";
    public string TargetFolder
    {
        get => _targetFolder;
        set { _targetFolder = value; OnPropertyChanged(); }
    }

    private string _passwordStrength = "";
    public string PasswordStrength
    {
        get => _passwordStrength;
        private set { _passwordStrength = value; OnPropertyChanged(); }
    }

    private bool _isWeakPassword;
    public bool IsWeakPassword
    {
        get => _isWeakPassword;
        private set { _isWeakPassword = value; OnPropertyChanged(); OnPropertyChanged(nameof(WeakWarningVisible)); }
    }

    public Visibility WeakWarningVisible => _isWeakPassword && !string.IsNullOrEmpty(Password)
        ? Visibility.Visible
        : Visibility.Collapsed;

    private bool _isBusy;
    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            _isBusy = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsIdle));
        }
    }

    public bool IsIdle => !_isBusy;

    private double _progressPercent;
    public double ProgressPercent
    {
        get => _progressPercent;
        set { _progressPercent = value; OnPropertyChanged(); }
    }

    private string _progressText = "";
    public string ProgressText
    {
        get => _progressText;
        set { _progressText = value; OnPropertyChanged(); }
    }

    private string _statusText = "就绪";
    public string StatusText
    {
        get => _statusText;
        set { _statusText = value; OnPropertyChanged(); }
    }

    private bool _isIndeterminate;
    public bool IsIndeterminate
    {
        get => _isIndeterminate;
        set { _isIndeterminate = value; OnPropertyChanged(); }
    }

    private string _speedText = "";
    public string SpeedText
    {
        get => _speedText;
        set { _speedText = value; OnPropertyChanged(); }
    }

    private string _etaText = "";
    public string EtaText
    {
        get => _etaText;
        set { _etaText = value; OnPropertyChanged(); }
    }

    private string _currentItem = "";
    public string CurrentItem
    {
        get => _currentItem;
        set { _currentItem = value; OnPropertyChanged(); OnPropertyChanged(nameof(CurrentItemVisible)); }
    }

    public Visibility CurrentItemVisible => string.IsNullOrEmpty(_currentItem)
        ? Visibility.Collapsed
        : Visibility.Visible;

    public ICommand AddFilesCommand { get; }
    public ICommand AddFolderCommand { get; }
    public ICommand ClearItemsCommand { get; }
    public ICommand RemoveItemCommand { get; }
    public ICommand BrowseOutputCommand { get; }
    public ICommand BrowseTargetCommand { get; }
    public ICommand BrowseContainerCommand { get; }
    public ICommand PrimaryCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand ToggleShowPasswordCommand { get; }

    public MainViewModel()
    {
        AddFilesCommand = new RelayCommand(_ => AddFiles());
        AddFolderCommand = new RelayCommand(_ => AddFolder());
        ClearItemsCommand = new RelayCommand(_ =>
        {
            Items.Clear();
            RefreshItemsSummary();
        }, _ => Items.Count > 0 && IsIdle);
        RemoveItemCommand = new RelayCommand(p =>
        {
            if (p is FileItemViewModel item)
            {
                Items.Remove(item);
                RefreshItemsSummary();
            }
        }, _ => IsIdle);
        BrowseOutputCommand = new RelayCommand(_ => BrowseOutput(), _ => IsIdle);
        BrowseTargetCommand = new RelayCommand(_ => BrowseTarget(), _ => IsIdle);
        BrowseContainerCommand = new RelayCommand(_ => BrowseContainer(), _ => IsIdle);
        PrimaryCommand = new AsyncRelayCommand(_ => RunPrimaryAsync(), _ => IsIdle);
        CancelCommand = new RelayCommand(_ => _cts?.Cancel(), _ => IsBusy);
        ToggleShowPasswordCommand = new RelayCommand(_ => ShowPassword = !ShowPassword);
    }

    public void AddPaths(IEnumerable<string> paths)
    {
        foreach (var path in paths)
        {
            try
            {
                if (File.Exists(path))
                {
                    var fi = new FileInfo(path);
                    Items.Add(new FileItemViewModel
                    {
                        FullPath = fi.FullName,
                        RelativePath = fi.Name,
                        IsDirectory = false,
                        SizeBytes = fi.Length,
                        SizeText = FormatSize(fi.Length)
                    });
                }
                else if (Directory.Exists(path))
                {
                    var di = new DirectoryInfo(path);
                    long dirBytes = 0;
                    try
                    {
                        foreach (var f in di.EnumerateFiles("*", SearchOption.AllDirectories))
                        {
                            dirBytes += f.Length;
                        }
                    }
                    catch
                    {
                        // 部分文件不可读时忽略
                    }
                    Items.Add(new FileItemViewModel
                    {
                        FullPath = di.FullName,
                        RelativePath = di.Name,
                        IsDirectory = true,
                        SizeBytes = dirBytes,
                        SizeText = dirBytes > 0 ? FormatSize(dirBytes) : "文件夹"
                    });
                }
            }
            catch
            {
                // 跳过无法读取的路径
            }
        }
        RefreshItemsSummary();
        OnPropertyChanged(nameof(Items));
    }

    private void AddFiles()
    {
        var dlg = new OpenFileDialog
        {
            Multiselect = true,
            Title = "选择要加密的文件"
        };
        if (dlg.ShowDialog() == true)
        {
            AddPaths(dlg.FileNames);
        }
    }

    private void AddFolder()
    {
        var dlg = new OpenFolderDialog
        {
            Title = "选择要加密的文件夹"
        };
        if (dlg.ShowDialog() == true)
        {
            AddPaths([dlg.FolderName]);
        }
    }

    private void BrowseOutput()
    {
        var dlg = new SaveFileDialog
        {
            Title = "保存加密文件",
            Filter = "yuexuan 加密文件 (*.yuexuan)|*.yuexuan",
            FileName = "加密文件.yuexuan",
            AddExtension = true,
            DefaultExt = ".yuexuan"
        };
        if (dlg.ShowDialog() == true)
        {
            OutputPath = dlg.FileName;
        }
    }

    private void BrowseTarget()
    {
        var dlg = new OpenFolderDialog
        {
            Title = "选择解密输出文件夹"
        };
        if (dlg.ShowDialog() == true)
        {
            TargetFolder = dlg.FolderName;
        }
    }

    private void BrowseContainer()
    {
        var dlg = new OpenFileDialog
        {
            Title = "选择加密文件",
            Filter = "yuexuan 加密文件 (*.yuexuan)|*.yuexuan|所有文件 (*.*)|*.*"
        };
        if (dlg.ShowDialog() == true)
        {
            OutputPath = dlg.FileName;
            try
            {
                var hint = DecryptPipeline.ReadHint(dlg.FileName);
                if (!string.IsNullOrEmpty(hint))
                {
                    StatusText = $"密码提示：{hint}";
                }
            }
            catch
            {
                // 忽略
            }
        }
    }

    private void UpdateStrength()
    {
        if (string.IsNullOrEmpty(Password))
        {
            PasswordStrength = "";
            IsWeakPassword = false;
            return;
        }

        int score = 0;
        if (Password.Length >= 8) score++;
        if (Password.Length >= 12) score++;
        if (Password.Any(char.IsLower) && Password.Any(char.IsUpper)) score++;
        if (Password.Any(char.IsDigit)) score++;
        if (Password.Any(c => !char.IsLetterOrDigit(c))) score++;

        bool inDictionary = IsCommonWeak(Password);
        if (inDictionary)
        {
            score = 0;
        }

        IsWeakPassword = inDictionary || Password.Length < 8 || score <= 1;
        PasswordStrength = score switch
        {
            <= 1 => "弱",
            2 or 3 => "中",
            4 => "强",
            _ => "很强"
        };
    }

    private static bool IsCommonWeak(string password)
    {
        string[] common =
        [
            "password", "123456", "12345678", "qwerty", "abc123", "111111",
            "123456789", "12345", "123123", "000000", "iloveyou", "admin",
            "password1", "qwerty123", "letmein", "welcome", "monkey", "dragon",
            "passw0rd", "p@ssw0rd", "666666", "888888", "password123"
        ];
        var lower = password.ToLowerInvariant();
        return common.Contains(lower) || lower.Length <= 4;
    }

    private async Task RunPrimaryAsync()
    {
        if (_mode == AppMode.Encrypt)
        {
            await RunEncryptAsync();
        }
        else
        {
            await RunDecryptAsync();
        }
    }

    private async Task RunEncryptAsync()
    {
        if (Items.Count == 0)
        {
            MessageBox.Show("请先添加要加密的文件或文件夹。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (string.IsNullOrEmpty(Password))
        {
            MessageBox.Show("请设置密码。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (Password != PasswordConfirm)
        {
            MessageBox.Show("两次输入的密码不一致。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (string.IsNullOrEmpty(OutputPath))
        {
            MessageBox.Show("请选择保存位置。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (IsWeakPassword)
        {
            var r = MessageBox.Show(
                "当前密码强度较弱，容易被猜到。\n忘记密码将无法恢复文件。\n\n仍要继续吗？",
                "文件加密",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (r != MessageBoxResult.Yes)
            {
                return;
            }
        }

        IsBusy = true;
        _cts = new CancellationTokenSource();
        ProgressPercent = 0;
        IsIndeterminate = true;
        StatusText = "正在派生密钥，请稍候…";

        try
        {
            var sources = Items.Select(i => new SourceItem(i.FullPath, i.RelativePath, i.IsDirectory)).ToList();
            var items = new List<SourceItem>();
            foreach (var s in sources)
            {
                if (s.IsDirectory)
                {
                    items.AddRange(CollectTree(s.FullPath, s.RelativePath));
                }
                else
                {
                    items.Add(new SourceItem(s.FullPath, s.RelativePath, false));
                }
            }
            var request = new EncryptRequest(
                items,
                Password,
                string.IsNullOrWhiteSpace(Hint) ? null : Hint.Trim(),
                OutputPath);

            var pipeline = new EncryptPipeline();
            var progress = new Progress<ProgressReport>(OnProgress);
            var result = await pipeline.EncryptAsync(request, progress, _cts.Token);
            ProgressPercent = 100;
            StatusText = $"加密完成：{result.FileCount} 个文件，{FormatSize(result.TotalBytes)}";
            var open = MessageBox.Show(
                $"加密完成。\n\n输出：{result.OutputPath}\n文件数：{result.FileCount}\n\n请妥善保管密码，忘记后无法恢复。\n原文件已保留。\n\n是否打开所在文件夹？",
                "文件加密",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);
            if (open == MessageBoxResult.Yes)
            {
                OpenContainingFolder(result.OutputPath);
            }
        }
        catch (CryptoException ex)
        {
            StatusText = "加密失败";
            MessageBox.Show(MapError(ex), "文件加密", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            StatusText = "加密失败";
            MessageBox.Show($"加密失败：{ex.Message}", "文件加密", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsBusy = false;
            IsIndeterminate = false;
            _cts?.Dispose();
            _cts = null;
            ClearSensitivePassword();
        }
    }

    private async Task RunDecryptAsync()
    {
        var container = OutputPath;
        if (string.IsNullOrEmpty(container) || !File.Exists(container))
        {
            MessageBox.Show("请选择有效的 .yuexuan 加密文件。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (string.IsNullOrEmpty(Password))
        {
            MessageBox.Show("请输入密码。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (string.IsNullOrEmpty(TargetFolder))
        {
            MessageBox.Show("请选择解密输出文件夹。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        IsBusy = true;
        _cts = new CancellationTokenSource();
        ProgressPercent = 0;
        IsIndeterminate = true;
        StatusText = "正在校验密码…";

        try
        {
            ConflictPolicy? stickyConflict = null;
            var request = new DecryptRequest(
                container,
                Password,
                TargetFolder,
                ConflictPolicy.Ask,
                (rel, full) =>
                {
                    if (stickyConflict is not null)
                    {
                        return stickyConflict.Value;
                    }

                    var result = System.Windows.Application.Current.Dispatcher.Invoke(() =>
                        ShowConflictDialog(rel));
                    if (result.Policy is null)
                    {
                        // 用户取消任务
                        _cts?.Cancel();
                        return ConflictPolicy.Skip;
                    }
                    if (result.ApplyToAll)
                    {
                        stickyConflict = result.Policy;
                    }
                    return result.Policy.Value;
                });

            var pipeline = new DecryptPipeline();
            var progress = new Progress<ProgressReport>(OnProgress);
            var result2 = await pipeline.DecryptAsync(request, progress, _cts.Token);
            ProgressPercent = 100;
            StatusText = $"解密完成：{result2.FileCount} 个文件";
            var open = MessageBox.Show(
                $"解密完成。\n\n输出目录：{TargetFolder}\n文件数：{result2.FileCount}\n跳过：{result2.Skipped}  改名：{result2.Renamed}\n\n是否打开输出文件夹？",
                "文件加密",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);
            if (open == MessageBoxResult.Yes)
            {
                OpenContainingFolder(TargetFolder);
            }
        }
        catch (CryptoException ex)
        {
            StatusText = "解密失败";
            MessageBox.Show(MapError(ex), "文件加密", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            StatusText = "解密失败";
            MessageBox.Show($"解密失败：{ex.Message}", "文件加密", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsBusy = false;
            IsIndeterminate = false;
            _cts?.Dispose();
            _cts = null;
            ClearSensitivePassword();
        }
    }

    /// <summary>操作结束后清空密码框，减少驻留。</summary>
    private void ClearSensitivePassword()
    {
        try
        {
            Password = "";
            PasswordConfirm = "";
            PasswordVisibilityChanged?.Invoke();
        }
        catch
        {
            // 忽略
        }
    }

    private static IEnumerable<SourceItem> CollectTree(string root, string rootName)
    {
        var list = new List<SourceItem>();
        foreach (var dir in Directory.EnumerateDirectories(root, "*", new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = false,
            AttributesToSkip = 0
        }))
        {
            var rel = rootName + "/" + Path.GetRelativePath(root, dir).Replace('\\', '/');
            if (YuexuanCrypto.Core.Security.PathGuard.TryNormalizeRelative(rel, out var norm))
            {
                list.Add(new SourceItem(dir, norm, true));
            }
        }
        foreach (var file in Directory.EnumerateFiles(root, "*", new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = false,
            AttributesToSkip = 0
        }))
        {
            var rel = rootName + "/" + Path.GetRelativePath(root, file).Replace('\\', '/');
            if (YuexuanCrypto.Core.Security.PathGuard.TryNormalizeRelative(rel, out var norm))
            {
                list.Add(new SourceItem(file, norm, false));
            }
        }
        if (!Directory.EnumerateFileSystemEntries(root).Any())
        {
            if (YuexuanCrypto.Core.Security.PathGuard.TryNormalizeRelative(rootName, out var n))
            {
                list.Add(new SourceItem(root, n, true));
            }
        }
        return list;
    }

    private void OnProgress(ProgressReport report)
    {
        IsIndeterminate = false;
        ProgressPercent = report.Percent;
        SpeedText = $"{FormatSize((long)report.BytesPerSecond)}/s";
        EtaText = report.Eta is { } eta ? $"预计剩余 {FormatTime(eta)}" : "";
        CurrentItem = report.CurrentItem ?? "";
        StatusText = report.Stage switch
        {
            OperationStage.Preparing => "正在准备…",
            OperationStage.ReadingSource => "正在读取…",
            OperationStage.Encrypting => "正在加密…",
            OperationStage.Writing => "正在写入…",
            OperationStage.Finalizing => "正在校验…",
            OperationStage.Decrypting => "正在解密…",
            OperationStage.Extracting => "正在写出…",
            OperationStage.Completed => "完成",
            OperationStage.Cancelled => "已取消",
            _ => "处理中…"
        };
        ProgressText = $"{FormatSize(report.BytesDone)} / {FormatSize(report.BytesTotal)}";
    }

    private static (ConflictPolicy? Policy, bool ApplyToAll) ShowConflictDialog(string relativePath)
    {
        var dialog = new Views.ConflictDialog(relativePath)
        {
            Owner = System.Windows.Application.Current.MainWindow
        };
        if (dialog.ShowDialog() == true)
        {
            return (dialog.SelectedPolicy, dialog.ApplyToAll);
        }
        return (null, false);
    }

    private static void OpenContainingFolder(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            var dir = File.Exists(full) ? Path.GetDirectoryName(full) : full;
            if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = dir,
                    UseShellExecute = true
                });
            }
        }
        catch
        {
            // 打开失败不影响主流程
        }
    }

    private static string MapError(CryptoException ex) => ex.Code switch
    {
        CryptoErrorCode.WrongPassword => "密码错误，或此文件需要使用配套软件解密。",
        CryptoErrorCode.Corrupted => "文件已损坏或不是有效的加密容器。",
        CryptoErrorCode.IntegrityFailed => "完整性校验失败：文件已损坏或被篡改。",
        CryptoErrorCode.Cancelled => "操作已取消。未完成的临时文件已清理，原文件未被修改。",
        CryptoErrorCode.PathUnsafe => "容器中包含不安全的路径，已拒绝解密。",
        CryptoErrorCode.DiskSpace => "磁盘空间不足。",
        CryptoErrorCode.SourceUnavailable => ex.Message,
        CryptoErrorCode.IoError => ex.Message,
        _ => ex.Message
    };

    private static string FormatSize(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double v = bytes;
        int i = 0;
        while (v >= 1024 && i < units.Length - 1)
        {
            v /= 1024;
            i++;
        }
        return i == 0 ? $"{bytes} B" : $"{v:0.##} {units[i]}";
    }

    private static string FormatTime(TimeSpan t)
    {
        if (t.TotalHours >= 1)
        {
            return $"{(int)t.TotalHours}小时{t.Minutes}分";
        }
        if (t.TotalMinutes >= 1)
        {
            return $"{(int)t.TotalMinutes}分{t.Seconds}秒";
        }
        return $"{Math.Max(0, (int)t.TotalSeconds)}秒";
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
