using System.Windows;
using YuexuanCrypto.Core.Pipeline;

namespace YuexuanCrypto.App.Views;

public partial class ConflictDialog : Window
{
    public ConflictPolicy SelectedPolicy { get; private set; } = ConflictPolicy.Skip;
    public bool ApplyToAll { get; private set; }

    public ConflictDialog(string relativePath)
    {
        InitializeComponent();
        FileNameText.Text = relativePath;
    }

    private void OnOverwrite(object sender, RoutedEventArgs e)
    {
        SelectedPolicy = ConflictPolicy.Overwrite;
        ApplyToAll = ApplyAllBox.IsChecked == true;
        DialogResult = true;
    }

    private void OnSkip(object sender, RoutedEventArgs e)
    {
        SelectedPolicy = ConflictPolicy.Skip;
        ApplyToAll = ApplyAllBox.IsChecked == true;
        DialogResult = true;
    }

    private void OnRename(object sender, RoutedEventArgs e)
    {
        SelectedPolicy = ConflictPolicy.Rename;
        ApplyToAll = ApplyAllBox.IsChecked == true;
        DialogResult = true;
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }
}
