using System;
using System.Windows;
using System.Windows.Threading;

namespace Passwordmanager
{
    public partial class App : Application
    {
        private const int SPLASH_DURATION = 3500; // 3.5 secondes

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Afficher l'écran de chargement
            SplashWindow splashWindow = new SplashWindow();
            splashWindow.Show();

            // Créer la fenêtre principale mais ne pas l'afficher encore
            MainWindow mainWindow = new MainWindow();

            // Créer un timer pour afficher la fenêtre principale après le délai
            DispatcherTimer timer = new DispatcherTimer();
            timer.Interval = TimeSpan.FromMilliseconds(SPLASH_DURATION);
            timer.Tick += (sender, args) =>
            {
                timer.Stop();

                // Important : d'abord afficher la fenêtre principale, 
                // puis fermer l'écran de chargement
                mainWindow.Show();
                splashWindow.Close();
            };

            timer.Start();
        }
    }
}
