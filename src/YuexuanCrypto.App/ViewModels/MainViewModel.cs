using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using YuexuanCrypto.Core.Pipeline;

namespace YuexuanCrypto.App.ViewModels;

public sealed class FileItemViewModel : INotifyPropertyChanged
{
    public string FullPath { get; init; } = "";
    public string RelativePath { get; init; } = "";
    public bool IsDirectory { get; init; }
    public long SizeBytes { get; init; }

    private string _sizeText = "";
    public string SizeText
    {
        get => _sizeText;
        set { _sizeText = value; OnPropertyChanged(); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
    public void Execute(object? parameter) => _execute(parameter);
}

public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<object?, Task> _execute;
    private readonly Func<object?, bool>? _canExecute;
    private bool _isRunning;

    public AsyncRelayCommand(Func<object?, Task> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter) => !_isRunning && (_canExecute?.Invoke(parameter) ?? true);

    public async void Execute(object? parameter)
    {
        if (_isRunning)
        {
            return;
        }
        _isRunning = true;
        CommandManager.InvalidateRequerySuggested();
        try
        {
            await _execute(parameter);
        }
        finally
        {
            _isRunning = false;
            CommandManager.InvalidateRequerySuggested();
        }
    }
}

/// <summary>
/// 加密 / 解密双栏同时展开的主界面模型。
/// 两侧字段独立；进度用操作序号隔离，避免旧任务回调污染新进度。
/// </summary>
public sealed class MainViewModel : INotifyPropertyChanged
{
    private CancellationTokenSource? _cts;
    private int _opSerial;

    // ---------- 加密区 ----------
    public ObservableCollection<FileItemViewModel> EncryptItems { get; } = [];

    private string _itemsSummary = "尚未添加项目";
    public string ItemsSummary
    {
        get => _itemsSummary;
        private set { _itemsSummary = value; OnPropertyChanged(); }
    }

    private string _encPassword = "";
    public string EncPassword
    {
        get => _encPassword;
        set { _encPassword = value; OnPropertyChanged(); UpdateStrength(); }
    }

    private string _encPasswordConfirm = "";
    public string EncPasswordConfirm
    {
        get => _encPasswordConfirm;
        set { _encPasswordConfirm = value; OnPropertyChanged(); }
    }

    private string _encHint = "";
    public string EncHint
    {
        get => _encHint;
        set { _encHint = value; OnPropertyChanged(); }
    }

    private string _encOutputPath = "";
    public string EncOutputPath
    {
        get => _encOutputPath;
        set { _encOutputPath = value; OnPropertyChanged(); }
    }

    // ---------- 解密区 ----------
    private string _decContainerPath = "";
    public string DecContainerPath
    {
        get => _decContainerPath;
        set
        {
            _decContainerPath = value;
            OnPropertyChanged();
            TryShowHintFromContainer();
        }
    }

    private string _decPassword = "";
    public string DecPassword
    {
        get => _decPassword;
        set { _decPassword = value; OnPropertyChanged(); }
    }

    private string _decTargetFolder = "";
    public string DecTargetFolder
    {
        get => _decTargetFolder;
        set { _decTargetFolder = value; OnPropertyChanged(); }
    }

    private string _decHint = "";
    public string DecHint
    {
        get => _decHint;
        set { _decHint = value; OnPropertyChanged(); OnPropertyChanged(nameof(DecHintVisible)); }
    }

    public Visibility DecHintVisible => string.IsNullOrEmpty(_decHint) ? Visibility.Collapsed : Visibility.Visible;

    // ---------- 密码强度（仅加密区显示） ----------
    private string _passwordStrength = "";
    public string PasswordStrength
    {
        get => _passwordStrength;
        private set { _passwordStrength = value; OnPropertyChanged(); OnPropertyChanged(nameof(StrengthBarWidth)); OnPropertyChanged(nameof(StrengthBarColor)); }
    }

    private bool _isWeakPassword;
    public bool IsWeakPassword
    {
        get => _isWeakPassword;
        private set { _isWeakPassword = value; OnPropertyChanged(); OnPropertyChanged(nameof(WeakWarningVisible)); }
    }

    public Visibility WeakWarningVisible => _isWeakPassword && !string.IsNullOrEmpty(EncPassword)
        ? Visibility.Visible
        : Visibility.Collapsed;

    public double StrengthBarWidth => PasswordStrength switch
    {
        "弱" => 40,
        "中" => 80,
        "强" => 120,
        "很强" => 160,
        _ => 0
    };

    public string StrengthBarColor => PasswordStrength switch
    {
        "弱" => "#F87171",
        "中" => "#FBBF24",
        "强" => "#34D399",
        "很强" => "#059669",
        _ => "#93C5FD"
    };

    // ---------- 共享进度 ----------
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

    // ---------- 显示密码 ----------
    private bool _showEncPassword;
    public bool ShowEncPassword
    {
        get => _showEncPassword;
        set
        {
            if (_showEncPassword == value)
            {
                return;
            }
            _showEncPassword = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(ShowEncPasswordGlyph));
            EncPasswordVisibilityChanged?.Invoke();
        }
    }

    public string ShowEncPasswordGlyph => _showEncPassword ? "🙈" : "👁";
    public event Action? EncPasswordVisibilityChanged;

    private bool _showDecPassword;
    public bool ShowDecPassword
    {
        get => _showDecPassword;
        set
        {
            if (_showDecPassword == value)
            {
                return;
            }
            _showDecPassword = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(ShowDecPasswordGlyph));
            DecPasswordVisibilityChanged?.Invoke();
        }
    }

    public string ShowDecPasswordGlyph => _showDecPassword ? "🙈" : "👁";
    public event Action? DecPasswordVisibilityChanged;

    // ---------- 命令 ----------
    public ICommand AddFilesCommand { get; }
    public ICommand AddFolderCommand { get; }
    public ICommand ClearItemsCommand { get; }
    public ICommand RemoveItemCommand { get; }
    public ICommand BrowseEncOutputCommand { get; }
    public ICommand BrowseDecContainerCommand { get; }
    public ICommand BrowseDecTargetCommand { get; }
    public ICommand EncryptCommand { get; }
    public ICommand DecryptCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand ToggleShowEncPasswordCommand { get; }
    public ICommand ToggleShowDecPasswordCommand { get; }

    public MainViewModel()
    {
        AddFilesCommand = new RelayCommand(_ => AddFiles(), _ => IsIdle);
        AddFolderCommand = new RelayCommand(_ => AddFolder(), _ => IsIdle);
        ClearItemsCommand = new RelayCommand(_ =>
        {
            EncryptItems.Clear();
            RefreshItemsSummary();
        }, _ => EncryptItems.Count > 0 && IsIdle);
        RemoveItemCommand = new RelayCommand(p =>
        {
            if (p is FileItemViewModel item)
            {
                EncryptItems.Remove(item);
                RefreshItemsSummary();
            }
        }, _ => IsIdle);
        BrowseEncOutputCommand = new RelayCommand(_ => BrowseEncOutput(), _ => IsIdle);
        BrowseDecContainerCommand = new RelayCommand(_ => BrowseDecContainer(), _ => IsIdle);
        BrowseDecTargetCommand = new RelayCommand(_ => BrowseDecTarget(), _ => IsIdle);
        EncryptCommand = new AsyncRelayCommand(_ => RunEncryptAsync(), _ => IsIdle);
        DecryptCommand = new AsyncRelayCommand(_ => RunDecryptAsync(), _ => IsIdle);
        CancelCommand = new RelayCommand(_ => _cts?.Cancel(), _ => IsBusy);
        ToggleShowEncPasswordCommand = new RelayCommand(_ => ShowEncPassword = !ShowEncPassword);
        ToggleShowDecPasswordCommand = new RelayCommand(_ => ShowDecPassword = !ShowDecPassword);
        RevealHintCommand = new RelayCommand(_ =>
        {
            DecHintRevealed = true;
        }, _ => !string.IsNullOrEmpty(DecHintPlainText));
    }

    public ICommand RevealHintCommand { get; }

    /// <summary>开始新任务前清空进度，避免串台。</summary>
    private void ResetProgress(string status)
    {
        ProgressPercent = 0;
        ProgressText = "";
        SpeedText = "";
        EtaText = "";
        CurrentItem = "";
        IsIndeterminate = true;
        StatusText = status;
    }

    private void RefreshItemsSummary()
    {
        if (EncryptItems.Count == 0)
        {
            ItemsSummary = "尚未添加项目";
            return;
        }
        int files = 0, dirs = 0;
        long bytes = 0;
        foreach (var i in EncryptItems)
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
        ItemsSummary = $"{EncryptItems.Count} 项（文件 {files} / 文件夹 {dirs}），约 {FormatSize(bytes)}";
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
                    EncryptItems.Add(new FileItemViewModel
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
                        // ignore
                    }
                    EncryptItems.Add(new FileItemViewModel
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
                // skip
            }
        }
        RefreshItemsSummary();

        // 若未选保存位置，给出默认建议，减少漏选
        if (string.IsNullOrWhiteSpace(EncOutputPath) && EncryptItems.Count > 0)
        {
            try
            {
                var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                if (!string.IsNullOrEmpty(desktop))
                {
                    EncOutputPath = Path.Combine(desktop, "加密文件.yuexuan");
                }
            }
            catch
            {
                // ignore
            }
        }
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
        var dlg = new OpenFolderDialog { Title = "选择要加密的文件夹" };
        if (dlg.ShowDialog() == true)
        {
            AddPaths([dlg.FolderName]);
        }
    }

    private void BrowseEncOutput()
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
            EncOutputPath = dlg.FileName;
        }
    }

    private void BrowseDecContainer()
    {
        var dlg = new OpenFileDialog
        {
            Title = "选择加密文件",
            Filter = "yuexuan 加密文件 (*.yuexuan)|*.yuexuan|所有文件 (*.*)|*.*"
        };
        if (dlg.ShowDialog() == true)
        {
            DecContainerPath = dlg.FileName;
            // 默认解密到容器同级的「解密输出」文件夹
            if (string.IsNullOrWhiteSpace(DecTargetFolder))
            {
                try
                {
                    var dir = Path.GetDirectoryName(dlg.FileName);
                    if (!string.IsNullOrEmpty(dir))
                    {
                        DecTargetFolder = Path.Combine(dir, "解密输出");
                    }
                }
                catch
                {
                    // ignore
                }
            }
        }
    }

    private void BrowseDecTarget()
    {
        var dlg = new OpenFolderDialog { Title = "选择解密输出文件夹" };
        if (dlg.ShowDialog() == true)
        {
            DecTargetFolder = dlg.FolderName;
        }
    }

    private void TryShowHintFromContainer()
    {
        try
        {
            if (string.IsNullOrEmpty(DecContainerPath) || !File.Exists(DecContainerPath))
            {
                DecHint = "";
                DecHintPlainText = "";
                return;
            }
            var hint = DecryptPipeline.ReadHint(DecContainerPath);
            DecHintPlainText = hint ?? "";
            // 默认不显示提示内容，避免旁人一眼看到线索
            DecHint = string.IsNullOrEmpty(hint) ? "" : "该文件含密码提示";
        }
        catch
        {
            DecHint = "";
            DecHintPlainText = "";
        }
    }

    private string _decHintPlainText = "";
    public string DecHintPlainText
    {
        get => _decHintPlainText;
        private set { _decHintPlainText = value; OnPropertyChanged(); OnPropertyChanged(nameof(DecHintToggleVisible)); }
    }

    public Visibility DecHintToggleVisible => string.IsNullOrEmpty(_decHintPlainText)
        ? Visibility.Collapsed
        : Visibility.Visible;

    private bool _decHintRevealed;
    public bool DecHintRevealed
    {
        get => _decHintRevealed;
        set
        {
            _decHintRevealed = value;
            OnPropertyChanged();
            DecHint = value && !string.IsNullOrEmpty(DecHintPlainText)
                ? $"密码提示：{DecHintPlainText}"
                : (string.IsNullOrEmpty(DecHintPlainText) ? "" : "该文件含密码提示");
        }
    }

    private void RevealDecHint() => DecHintRevealed = true;

    private void UpdateStrength()
    {
        if (string.IsNullOrEmpty(EncPassword))
        {
            PasswordStrength = "";
            IsWeakPassword = false;
            return;
        }

        int score = 0;
        if (EncPassword.Length >= 8) score++;
        if (EncPassword.Length >= 12) score++;
        if (EncPassword.Any(char.IsLower) && EncPassword.Any(char.IsUpper)) score++;
        if (EncPassword.Any(char.IsDigit)) score++;
        if (EncPassword.Any(c => !char.IsLetterOrDigit(c))) score++;

        bool inDictionary = IsCommonWeak(EncPassword);
        if (inDictionary)
        {
            score = 0;
        }

        IsWeakPassword = inDictionary || EncPassword.Length < 8 || score <= 1;
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

    private async Task RunEncryptAsync()
    {
        if (EncryptItems.Count == 0)
        {
            MessageBox.Show("请先添加要加密的文件或文件夹。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (string.IsNullOrEmpty(EncPassword))
        {
            MessageBox.Show("请设置密码。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (EncPassword != EncPasswordConfirm)
        {
            MessageBox.Show("两次输入的密码不一致。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (string.IsNullOrEmpty(EncOutputPath))
        {
            MessageBox.Show("请选择保存位置。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        // 防静默覆盖：目标已存在则明确询问
        try
        {
            var fullOut = Path.GetFullPath(EncOutputPath);
            if (!fullOut.EndsWith(".yuexuan", StringComparison.OrdinalIgnoreCase))
            {
                fullOut += ".yuexuan";
            }
            if (File.Exists(fullOut))
            {
                var r = MessageBox.Show(
                    $"目标文件已存在：\n{fullOut}\n\n是否覆盖？",
                    "文件加密",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);
                if (r != MessageBoxResult.Yes)
                {
                    return;
                }
            }
        }
        catch
        {
            // 路径异常时继续，由底层报错
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
        int serial = ++_opSerial;
        ResetProgress("正在派生密钥，请稍候…");

        try
        {
            var items = new List<SourceItem>();
            foreach (var s in EncryptItems)
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
                EncPassword,
                string.IsNullOrWhiteSpace(EncHint) ? null : EncHint.Trim(),
                EncOutputPath);

            var pipeline = new EncryptPipeline();
            var progress = new Progress<ProgressReport>(r => OnProgress(serial, r));
            var result = await pipeline.EncryptAsync(request, progress, _cts.Token);
            if (serial != _opSerial)
            {
                return;
            }
            ProgressPercent = 100;
            IsIndeterminate = false;
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
            if (serial == _opSerial)
            {
                IsBusy = false;
                IsIndeterminate = false;
            }
            _cts?.Dispose();
            _cts = null;
            // 保留密码便于连续操作；仅在“显示密码”状态下收起明文
            ShowEncPassword = false;
        }
    }

    private async Task RunDecryptAsync()
    {
        if (string.IsNullOrEmpty(DecContainerPath) || !File.Exists(DecContainerPath))
        {
            MessageBox.Show("请选择有效的 .yuexuan 加密文件。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (string.IsNullOrEmpty(DecPassword))
        {
            MessageBox.Show("请输入密码。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (string.IsNullOrEmpty(DecTargetFolder))
        {
            MessageBox.Show("请选择解密输出文件夹。", "文件加密", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        IsBusy = true;
        _cts = new CancellationTokenSource();
        int serial = ++_opSerial;
        ResetProgress("正在校验密码…");

        try
        {
            ConflictPolicy? stickyConflict = null;
            var request = new DecryptRequest(
                DecContainerPath,
                DecPassword,
                DecTargetFolder,
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
            var progress = new Progress<ProgressReport>(r => OnProgress(serial, r));
            var result2 = await pipeline.DecryptAsync(request, progress, _cts.Token);
            if (serial != _opSerial)
            {
                return;
            }
            ProgressPercent = 100;
            IsIndeterminate = false;
            StatusText = $"解密完成：{result2.FileCount} 个文件";
            var open = MessageBox.Show(
                $"解密完成。\n\n输出目录：{DecTargetFolder}\n文件数：{result2.FileCount}\n跳过：{result2.Skipped}  改名：{result2.Renamed}\n\n是否打开输出文件夹？",
                "文件加密",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);
            if (open == MessageBoxResult.Yes)
            {
                OpenContainingFolder(DecTargetFolder);
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
            if (serial == _opSerial)
            {
                IsBusy = false;
                IsIndeterminate = false;
            }
            _cts?.Dispose();
            _cts = null;
            ShowDecPassword = false;
        }
    }

    /// <summary>只接受当前操作序号的进度，防止旧任务串台。</summary>
    private void OnProgress(int serial, ProgressReport report)
    {
        if (serial != _opSerial)
        {
            return;
        }
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
            // ignore
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
