using System;
using System.IO;
using Microsoft.UI.Xaml;

namespace KohaneStation;

/// <summary>
/// Application entry: owns the single main window. The Kohane index workstation is an
/// unpackaged WinUI 3 app (WindowsPackageType=None) so it runs straight on this machine's
/// installed Windows App Runtime without an MSIX identity.
/// </summary>
public partial class App : Application
{
    private Window? _window;

    /// <summary>
    /// Startup trace. An unpackaged WinUI app has nowhere to print a startup failure, so each
    /// milestone is appended next to the executable. Set KOHANE_STATION_TRACE=0 to silence it.
    /// </summary>
    internal static void Trace(string message)
    {
        if (Environment.GetEnvironmentVariable("KOHANE_STATION_TRACE") == "0") return;
        try
        {
            File.AppendAllText(
                Path.Combine(AppContext.BaseDirectory, "startup.log"),
                $"{DateTime.Now:HH:mm:ss.fff}  {message}{Environment.NewLine}");
        }
        catch
        {
            // a trace that throws would be worse than no trace
        }
    }

    public App()
    {
        Trace("App ctor: enter");
        InitializeComponent();
        Trace("App ctor: InitializeComponent done");
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        Trace("OnLaunched: enter");
        _window = new MainWindow();
        Trace("OnLaunched: MainWindow constructed");
        _window.Activate();
        Trace("OnLaunched: Activate returned");
    }
}
