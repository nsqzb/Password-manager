using System.Windows;


namespace Passwordmanager
{
    /// <summary>
    /// Logique d'interaction pour SplashWindow.xaml
    /// </summary>
    public partial class SplashWindow : Window
    {
        public SplashWindow()
        {
            InitializeComponent();

            // L'écran de chargement se fermera automatiquement
            // après la durée définie dans App.xaml.cs
        }
    }
}
