using System.IO;
using System.Windows;
using System.Windows.Data;
using YuexuanCrypto.App.ViewModels;

namespace YuexuanCrypto.App;

public partial class MainWindow : Window
{
    private MainViewModel ViewModel => (MainViewModel)DataContext;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        PreviewKeyDown += OnPreviewKeyDown;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        UpdateTitleVisibility();
        ViewModel.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName is nameof(MainViewModel.IsEncryptMode) or nameof(MainViewModel.IsDecryptMode))
            {
                UpdateTitleVisibility();
            }
        };
        ViewModel.PasswordVisibilityChanged += SyncPasswordVisibility;
    }

    private void SyncPasswordVisibility()
    {
        // WPF PasswordBox 不支持绑定明文；显示密码时改用 TextBox 同步
        if (ViewModel.ShowPassword)
        {
            PwdBox.Visibility = Visibility.Collapsed;
            PwdVisibleBox.Visibility = Visibility.Visible;
            if (PwdVisibleBox.Text != ViewModel.Password)
            {
                PwdVisibleBox.Text = ViewModel.Password;
            }
        }
        else
        {
            PwdVisibleBox.Visibility = Visibility.Collapsed;
            PwdBox.Visibility = Visibility.Visible;
            if (PwdBox.Password != ViewModel.Password)
            {
                PwdBox.Password = ViewModel.Password;
            }
        }
        if (ConfirmBox.Password != ViewModel.PasswordConfirm)
        {
            ConfirmBox.Password = ViewModel.PasswordConfirm;
        }
    }

    private void OnPreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Escape && ViewModel.IsBusy)
        {
            ViewModel.CancelCommand.Execute(null);
            e.Handled = true;
            return;
        }
        if (e.Key == System.Windows.Input.Key.Enter
            && ViewModel.IsIdle
            && !(System.Windows.Input.Keyboard.FocusedElement is System.Windows.Controls.TextBox))
        {
            if (ViewModel.PrimaryCommand.CanExecute(null))
            {
                ViewModel.PrimaryCommand.Execute(null);
            }
            e.Handled = true;
        }
    }

    private void UpdateTitleVisibility()
    {
        ListTitle.Text = ViewModel.IsEncryptMode ? "待加密项目" : "加密文件";
        ConfirmLabel.Visibility = ViewModel.IsEncryptMode ? Visibility.Visible : Visibility.Collapsed;
        ConfirmBox.Visibility = ViewModel.IsEncryptMode ? Visibility.Visible : Visibility.Collapsed;
        HintLabel.Visibility = ViewModel.IsEncryptMode ? Visibility.Visible : Visibility.Collapsed;
        HintHelp.Visibility = ViewModel.IsEncryptMode ? Visibility.Visible : Visibility.Collapsed;
        OutputLabel.Text = ViewModel.IsEncryptMode ? "保存位置" : "加密文件";
    }

    private void OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            vm.Password = PwdBox.Password;
        }
    }

    private void OnPasswordVisibleChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (DataContext is MainViewModel vm && PwdVisibleBox is not null && vm.Password != PwdVisibleBox.Text)
        {
            vm.Password = PwdVisibleBox.Text;
            if (PwdBox.Password != PwdVisibleBox.Text)
            {
                PwdBox.Password = PwdVisibleBox.Text;
            }
        }
    }

    private void OnConfirmChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            vm.PasswordConfirm = ConfirmBox.Password;
        }
    }

    private void OnAboutClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        var about = new AboutWindow { Owner = this };
        about.ShowDialog();
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Copy;
        }
        else
        {
            e.Effects = DragDropEffects.None;
        }
        e.Handled = true;
    }

    private void OnDrop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is not string[] paths || paths.Length == 0)
        {
            return;
        }

        var isYuexuan = paths.Length == 1
            && paths[0].EndsWith(".yuexuan", StringComparison.OrdinalIgnoreCase)
            && File.Exists(paths[0]);

        if (isYuexuan)
        {
            ViewModel.IsDecryptMode = true;
            ViewModel.OutputPath = paths[0];
            var hint = YuexuanCrypto.Core.Pipeline.DecryptPipeline.ReadHint(paths[0]);
            ViewModel.StatusText = string.IsNullOrEmpty(hint) ? "已选择加密文件，请输入密码" : $"密码提示：{hint}";
            return;
        }

        ViewModel.AddPaths(paths);
    }
}
