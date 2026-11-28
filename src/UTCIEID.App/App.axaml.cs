using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using UTCie.Linux;

namespace UTCIEID.App;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);
    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var vault = new EncryptedCardVault();
            var model = new MainViewModel(new NfcdReader(), Program.StartupLink, vault
#if LEGACY_MIGRATION
                , legacyCredentials: new SecretServicePinStore()
#endif
            );
            desktop.MainWindow = new MainWindow { DataContext = model };
            desktop.Exit += (_, _) => vault.Dispose();
        }
        base.OnFrameworkInitializationCompleted();
    }
}
