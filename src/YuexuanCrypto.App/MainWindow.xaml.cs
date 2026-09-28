using System.IO;
using System.Windows;
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
        ViewModel.EncPasswordVisibilityChanged += SyncEncPasswordVisibility;
        ViewModel.DecPasswordVisibilityChanged += SyncDecPasswordVisibility;
    }

    private void SyncEncPasswordVisibility()
    {
        if (ViewModel.ShowEncPassword)
        {
            EncPwdBox.Visibility = Visibility.Collapsed;
            EncPwdVisibleBox.Visibility = Visibility.Visible;
            if (EncPwdVisibleBox.Text != ViewModel.EncPassword)
            {
                EncPwdVisibleBox.Text = ViewModel.EncPassword;
            }
        }
        else
        {
            EncPwdVisibleBox.Visibility = Visibility.Collapsed;
            EncPwdBox.Visibility = Visibility.Visible;
            if (EncPwdBox.Password != ViewModel.EncPassword)
            {
                EncPwdBox.Password = ViewModel.EncPassword;
            }
        }
        if (EncConfirmBox.Password != ViewModel.EncPasswordConfirm)
        {
            EncConfirmBox.Password = ViewModel.EncPasswordConfirm;
        }
    }

    private void SyncDecPasswordVisibility()
    {
        if (ViewModel.ShowDecPassword)
        {
            DecPwdBox.Visibility = Visibility.Collapsed;
            DecPwdVisibleBox.Visibility = Visibility.Visible;
            if (DecPwdVisibleBox.Text != ViewModel.DecPassword)
            {
                DecPwdVisibleBox.Text = ViewModel.DecPassword;
            }
        }
        else
        {
            DecPwdVisibleBox.Visibility = Visibility.Collapsed;
            DecPwdBox.Visibility = Visibility.Visible;
            if (DecPwdBox.Password != ViewModel.DecPassword)
            {
                DecPwdBox.Password = ViewModel.DecPassword;
            }
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

        if (e.Key == System.Windows.Input.Key.Enter && ViewModel.IsIdle)
        {
            // 焦点在哪一侧就触发哪一侧
            var focused = System.Windows.Input.Keyboard.FocusedElement as DependencyObject;
            bool inDecrypt = false;
            while (focused is not null)
            {
                if (focused is System.Windows.Controls.TextBox tb && tb.Name.StartsWith("Dec", StringComparison.OrdinalIgnoreCase))
                {
                    inDecrypt = true;
                    break;
                }
                if (focused is System.Windows.Controls.PasswordBox pb && pb.Name.StartsWith("Dec", StringComparison.OrdinalIgnoreCase))
                {
                    inDecrypt = true;
                    break;
                }
                focused = System.Windows.Media.VisualTreeHelper.GetParent(focused);
            }

            var cmd = inDecrypt ? ViewModel.DecryptCommand : ViewModel.EncryptCommand;
            if (cmd.CanExecute(null))
            {
                cmd.Execute(null);
            }
            e.Handled = true;
        }
    }

    private void OnEncPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            vm.EncPassword = EncPwdBox.Password;
        }
    }

    private void OnEncPasswordVisibleChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (DataContext is MainViewModel vm && vm.EncPassword != EncPwdVisibleBox.Text)
        {
            vm.EncPassword = EncPwdVisibleBox.Text;
            if (EncPwdBox.Password != EncPwdVisibleBox.Text)
            {
                EncPwdBox.Password = EncPwdVisibleBox.Text;
            }
        }
    }

    private void OnEncConfirmChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            vm.EncPasswordConfirm = EncConfirmBox.Password;
        }
    }

    private void OnDecPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            vm.DecPassword = DecPwdBox.Password;
        }
    }

    private void OnDecPasswordVisibleChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (DataContext is MainViewModel vm && vm.DecPassword != DecPwdVisibleBox.Text)
        {
            vm.DecPassword = DecPwdVisibleBox.Text;
            if (DecPwdBox.Password != DecPwdVisibleBox.Text)
            {
                DecPwdBox.Password = DecPwdVisibleBox.Text;
            }
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
            ViewModel.DecContainerPath = paths[0];
            return;
        }

        ViewModel.AddPaths(paths);
    }
}
