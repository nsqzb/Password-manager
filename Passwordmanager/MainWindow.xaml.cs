using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Collections.Generic;
using Microsoft.Data.Sqlite;
using System.Windows.Controls;
using System.Windows;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Windows.Media.Imaging;
using System.Reflection;
using System.Data.SQLite;
using Microsoft.Win32;
using System.Net.Http;
using System.Threading.Tasks;
using System.ComponentModel;

namespace Passwordmanager
{
    public class PasswordEntry : INotifyPropertyChanged
    {
        public int Id { get; set; }
        public string ServiceName { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }

        private BitmapImage _logo;
        public BitmapImage Logo
        {
            get => _logo;
            set
            {
                _logo = value;
                OnPropertyChanged(nameof(Logo));
            }
        }
        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public async Task LoadLogoAsync()
        {
            if (Logo == null)
            {
                Logo = await LogoLoader.LoadLogoAsync(ServiceName);
            }
        }
    }

    public class LogoLoader
    {
        private static readonly HttpClient client = new HttpClient();

        public static async Task<BitmapImage> LoadLogoAsync(string serviceName)
        {
            string logoUrl = GetLogoUrl(serviceName);
            return await LoadImageFromUrlAsync(logoUrl);
        }

        private static string GetLogoUrl(string serviceName)
        {
            // Extraire un domaine à partir du nom de service
            string domain = serviceName.ToLower();

            if (domain.Contains("@"))
            {
                domain = domain.Split('@')[1];
            }
            else if (domain.Contains("/"))
            {
                Uri uri;
                if (Uri.TryCreate(domain, UriKind.Absolute, out uri))
                {
                    domain = uri.Host;
                }
            }
            else if (!domain.Contains("."))
            {
                domain = domain + ".com";
            }

            // Utiliser l'API Clearbit Logo
            return $"https://logo.clearbit.com/{domain}";
        }

        public static async Task<BitmapImage> LoadImageFromUrlAsync(string url)
        {
            try
            {
                byte[] imageData = await client.GetByteArrayAsync(url);

                using (var ms = new MemoryStream(imageData))
                {
                    var image = new BitmapImage();
                    image.BeginInit();
                    image.CacheOption = BitmapCacheOption.OnLoad;
                    image.StreamSource = ms;
                    image.EndInit();
                    image.Freeze(); // Important pour l'accès multi-thread
                    return image;
                }
            }
            catch
            {
                return null;
            }
        }
    }

    public partial class MainWindow : Window
    {
        private string storedMasterPasswordHash = "";
        private byte[] encryptionKey = Array.Empty<byte>();
        private string tempImportFilePath = "";

        public MainWindow()
        {
            InitializeComponent();
            InitializeDatabase();
            RetrieveMasterPasswordHashFromDatabase();

            if (string.IsNullOrEmpty(storedMasterPasswordHash))
            {
                PromptSetMasterPassword();
            }
            else
            {
                popupMasterPassword.IsOpen = true;
            }
        }

        private void InitializeDatabase()
        {
            try
            {
                // Construct the data folder and file path
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");

                // Check for database folder
                if (!Directory.Exists(dataFolderPath))
                {
                    Directory.CreateDirectory(dataFolderPath);
                }

                // Connect to the database
                using (SQLiteConnection connection = new SQLiteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    // Create Database tables
                    using (SQLiteCommand command = new SQLiteCommand(connection))
                    {
                        command.CommandText = @"CREATE TABLE IF NOT EXISTS Passwords (
                                            Id INTEGER PRIMARY KEY,
                                            ServiceName TEXT,
                                            Username TEXT,
                                            Password TEXT
                                        );";
                        command.ExecuteNonQuery();
                    }

                    using (SQLiteCommand command = new SQLiteCommand(connection))
                    {
                        command.CommandText = @"CREATE TABLE IF NOT EXISTS MasterPassword (
                                            Id INTEGER PRIMARY KEY,
                                            PasswordHash TEXT
                                        );";
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error initializing database: {ex.Message}");
            }
        }

        private void RetrieveMasterPasswordHashFromDatabase()
        {
            try
            {
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");

                using (var connection = new SqliteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT PasswordHash FROM MasterPassword";
                        var result = command.ExecuteScalar();
                        if (result != null)
                        {
                            storedMasterPasswordHash = result.ToString();
                            InitializeEncryptionKey(storedMasterPasswordHash);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error retrieving master password hash from database: {ex.Message}");
            }
        }

        private void PromptSetMasterPassword()
        {
            popupSetMasterPassword.IsOpen = true;
        }

        private void SetMasterPassword(string masterPassword)
        {
            try
            {
                string passwordHash = BCrypt.Net.BCrypt.HashPassword(masterPassword, BCrypt.Net.BCrypt.GenerateSalt());
                storedMasterPasswordHash = passwordHash;
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");
                using (var connection = new SqliteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "INSERT INTO MasterPassword (PasswordHash) VALUES (@PasswordHash)";
                        command.Parameters.AddWithValue("@PasswordHash", passwordHash);
                        command.ExecuteNonQuery();
                    }
                }

                InitializeEncryptionKey(storedMasterPasswordHash);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error setting master password: {ex.Message}");
            }
        }

        private void InitializeEncryptionKey(string masterPasswordHash)
        {
            if (!string.IsNullOrEmpty(masterPasswordHash))
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(masterPasswordHash);
                Array.Resize(ref keyBytes, 32);
                encryptionKey = keyBytes;
            }
            else
            {
                MessageBox.Show("Master password hash is empty or null.");
            }
        }

        private string EncryptString(string plainText)
        {
            if (encryptionKey != null && encryptionKey.Length > 0)
            {
                using (var aesAlg = Aes.Create())
                {
                    aesAlg.Key = encryptionKey;
                    aesAlg.Mode = CipherMode.CBC;
                    aesAlg.GenerateIV();

                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                        msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);

                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }

                        return Convert.ToBase64String(msEncrypt.ToArray());
                    }
                }
            }
            else
            {
                MessageBox.Show("Encryption key is not initialized.");
                return string.Empty;
            }
        }

        private string DecryptString(string cipherText)
        {
            if (encryptionKey != null && encryptionKey.Length > 0)
            {
                try
                {
                    byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

                    using (var aesAlg = Aes.Create())
                    {
                        aesAlg.Key = encryptionKey;
                        aesAlg.Mode = CipherMode.CBC;
                        int ivLength = BitConverter.ToInt32(cipherTextBytes, 0);
                        aesAlg.IV = cipherTextBytes.Skip(sizeof(int)).Take(ivLength).ToArray();

                        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                        using (MemoryStream msDecrypt = new MemoryStream(cipherTextBytes, sizeof(int) + ivLength, cipherTextBytes.Length - (sizeof(int) + ivLength)))
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
                catch (CryptographicException)
                {
                    return null;
                }
                catch
                {
                    return null;
                }
            }
            else
            {
                MessageBox.Show("Encryption key is not initialized.");
                return string.Empty;
            }
        }

        private void BtnSubmitEnterMasterPassword_Click(object sender, RoutedEventArgs e)
        {
            string masterPassword = txtEnterMasterPassword.Password;
            if (ValidateMasterPassword(masterPassword))
            {
                DecryptAndDisplayPasswords(masterPassword);
                popupMasterPassword.IsOpen = false;

                DataGrid.Visibility = Visibility.Visible;
                DataGrid.ItemsSource = GetPasswords();
            }
            else
            {
                MessageBox.Show("Invalid master password!");
            }
        }

        private bool ValidateMasterPassword(string masterPassword)
        {
            return BCrypt.Net.BCrypt.Verify(masterPassword, storedMasterPasswordHash);
        }

        private void DecryptAndDisplayPasswords(string masterPassword)
        {
            List<PasswordEntry> decryptedPasswords = DecryptPasswords(masterPassword);
            DataGrid.ItemsSource = decryptedPasswords;
        }

        private List<PasswordEntry> DecryptPasswords(string masterPassword)
        {
            List<PasswordEntry> decryptedPasswords = new List<PasswordEntry>();

            try
            {
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");

                using (var connection = new SqliteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT * FROM Passwords";
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                PasswordEntry entry = new PasswordEntry
                                {
                                    Id = reader.GetInt32(0),
                                    ServiceName = DecryptString(reader.GetString(1)),
                                    Username = DecryptString(reader.GetString(2)),
                                    Password = DecryptString(reader.GetString(3))
                                };
                                decryptedPasswords.Add(entry);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error decrypting passwords: {ex.Message}");
            }

            return decryptedPasswords;
        }

        private void BtnSubmitSetMasterPassword_Click(object sender, RoutedEventArgs e)
        {
            string masterPassword = txtSetMasterPassword.Password;
            SetMasterPassword(masterPassword);
            popupSetMasterPassword.IsOpen = false;
            popupMasterPassword.IsOpen = true;
        }

        private void BtnAdd_Click(object sender, RoutedEventArgs e)
        {
            string service = txtService.Text;
            string username = txtUsername.Text;
            string password = txtPassword.Password;

            SavePassword(service, username, password);
            DataGrid.ItemsSource = GetPasswords();

            txtService.Clear();
            txtUsername.Clear();
            txtPassword.Clear();
        }

        private void SavePassword(string serviceName, string username, string password)
        {
            try
            {
                string encryptedServiceName = EncryptString(serviceName);
                string encryptedUsername = EncryptString(username);
                string encryptedPassword = EncryptString(password);
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");
                using (var connection = new SqliteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "INSERT INTO Passwords (ServiceName, Username, Password) VALUES (@ServiceName, @Username, @Password)";
                        command.Parameters.AddWithValue("@ServiceName", encryptedServiceName);
                        command.Parameters.AddWithValue("@Username", encryptedUsername);
                        command.Parameters.AddWithValue("@Password", encryptedPassword);
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving password: {ex.Message}");
            }
        }

        private List<PasswordEntry> GetPasswords()
        {
            List<PasswordEntry> passwords = new List<PasswordEntry>();
            try
            {
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");

                using (var connection = new SqliteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT * FROM Passwords";
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                PasswordEntry entry = new PasswordEntry
                                {
                                    Id = reader.GetInt32(0),
                                    ServiceName = DecryptString(reader.GetString(1)),
                                    Username = DecryptString(reader.GetString(2)),
                                    Password = DecryptString(reader.GetString(3))
                                };
                                passwords.Add(entry);

                                // Chargement asynchrone du logo
                                Task.Run(() => entry.LoadLogoAsync());
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error retrieving passwords: {ex.Message}");
            }

            return passwords;
        }

        private void BtnDelete_Click(object sender, RoutedEventArgs e)
        {
            PasswordEntry selectedEntry = (PasswordEntry)DataGrid.SelectedItem;
            if (selectedEntry != null)
            {
                DeletePassword(selectedEntry.Id);
                DataGrid.ItemsSource = GetPasswords();
            }
        }

        private void DeletePassword(int id)
        {
            try
            {
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");

                using (var connection = new SqliteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "DELETE FROM Passwords WHERE Id = @Id";
                        command.Parameters.AddWithValue("@Id", id);
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error deleting password: {ex.Message}");
            }
        }

        private string GeneratePassword(int length)
        {
            const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_-+=<>?";
            StringBuilder res = new StringBuilder();
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] uintBuffer = new byte[sizeof(uint)];

                while (length-- > 0)
                {
                    rng.GetBytes(uintBuffer);
                    uint num = BitConverter.ToUInt32(uintBuffer, 0);
                    res.Append(valid[(int)(num % (uint)valid.Length)]);
                }
            }
            return res.ToString();
        }

        private void BtnGenerate_Click(object sender, RoutedEventArgs e)
        {
            string generatedPassword = GeneratePassword(16);
            txtGeneratedPassword.Text = generatedPassword;
        }

        private void BtnImportDatabase_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "SQLite Database Files (*.db)|*.db",
                Title = "Sélectionnez le fichier de base de données à importer"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                tempImportFilePath = openFileDialog.FileName;
                PromptForImportPassword();
            }
        }

        private void PromptForImportPassword()
        {
            var passwordBox = new PasswordBox();
            var dialog = new Window
            {
                Title = "Mot de passe de la base de données",
                Content = new StackPanel
                {
                    Children =
                    {
                        new TextBlock { Text = "Entrez le mot de passe maître de la base de données à importer:" },
                        passwordBox,
                        new Button { Content = "OK", IsDefault = true }
                    }
                },
                Width = 350,
                Height = 150,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this
            };

            var okButton = ((StackPanel)dialog.Content).Children.OfType<Button>().FirstOrDefault();
            if (okButton != null)
            {
                okButton.Click += (s, args) =>
                {
                    dialog.DialogResult = true;
                    dialog.Close();
                };
            }

            if (dialog.ShowDialog() == true)
            {
                string importPassword = passwordBox.Password;
                ValidateImportPassword(importPassword);
            }
        }

        private void ValidateImportPassword(string importPassword)
        {
            if (string.IsNullOrEmpty(tempImportFilePath))
            {
                MessageBox.Show("Aucun fichier à importer.");
                return;
            }

            string uniqueId = Guid.NewGuid().ToString();
            string tempDbFile = Path.Combine(Path.GetTempPath(), $"temp_import_{uniqueId}.db");

            SqliteConnection tempConnection = null;

            try
            {
                File.Copy(tempImportFilePath, tempDbFile, true);

                byte[] currentKey = encryptionKey;

                string importPasswordHash = null;

                try
                {
                    tempConnection = new SqliteConnection($"Data Source={tempDbFile}");
                    tempConnection.Open();

                    using (var command = tempConnection.CreateCommand())
                    {
                        command.CommandText = "SELECT PasswordHash FROM MasterPassword";
                        var result = command.ExecuteScalar();
                        if (result != null)
                        {
                            importPasswordHash = result.ToString();
                        }
                    }
                }
                finally
                {
                    if (tempConnection != null)
                    {
                        tempConnection.Close();
                        tempConnection.Dispose();
                        tempConnection = null;
                    }

                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }

                if (importPasswordHash == null)
                {
                    MessageBox.Show("La base de données importée ne contient pas de mot de passe maître.");
                    return;
                }

                bool isPasswordValid = BCrypt.Net.BCrypt.Verify(importPassword, importPasswordHash);

                if (isPasswordValid)
                {
                    var result = MessageBox.Show(
                        "Base de données valide. L'importation va remplacer votre base de données actuelle. Voulez-vous continuer?",
                        "Confirmation d'importation",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);

                    if (result == MessageBoxResult.Yes)
                    {
                        string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                        string destinationFilePath = Path.Combine(dataFolderPath, "passwords.db");

                        GC.Collect();
                        GC.WaitForPendingFinalizers();

                        File.Copy(tempImportFilePath, destinationFilePath, true);
                        MessageBox.Show("Base de données importée avec succès !");

                        RetrieveMasterPasswordHashFromDatabase();

                        MessageBox.Show("Veuillez vous connecter avec le mot de passe de la base de données importée.");
                        popupMasterPassword.IsOpen = true;
                    }
                }
                else
                {
                    MessageBox.Show("Mot de passe incorrect pour la base de données importée.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Erreur lors de la validation de la base de données : {ex.Message}");
            }
            finally
            {
                if (tempConnection != null)
                {
                    tempConnection.Close();
                    tempConnection.Dispose();
                }

                GC.Collect();
                GC.WaitForPendingFinalizers();

                for (int i = 0; i < 5; i++)
                {
                    try
                    {
                        if (File.Exists(tempDbFile))
                        {
                            File.Delete(tempDbFile);
                            break;
                        }
                    }
                    catch
                    {
                        System.Threading.Thread.Sleep(500);
                    }
                }
            }
        }

        private void BtnExportDatabase_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog
            {
                Filter = "SQLite Database Files (*.db)|*.db",
                Title = "Sélectionnez l'emplacement pour exporter la base de données",
                FileName = "passwords.db"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                string destinationFilePath = saveFileDialog.FileName;
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string sourceFilePath = Path.Combine(dataFolderPath, "passwords.db");

                try
                {
                    File.Copy(sourceFilePath, destinationFilePath, true);
                    MessageBox.Show("Base de données exportée avec succès !");
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Erreur lors de l'exportation de la base de données : {ex.Message}");
                }
            }
        }

        // Nouvelles méthodes pour la copie sur double-clic
        private void CopyUsername_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2) // Double-clic
            {
                Grid grid = sender as Grid;
                if (grid != null)
                {
                    PasswordEntry entry = grid.DataContext as PasswordEntry;
                    if (entry != null)
                    {
                        CopyToClipboard(entry.Username);
                        ShowCopyFeedback("Identifiant copié dans le presse-papiers !");
                    }
                }
            }
        }

        private void CopyPassword_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2) // Double-clic
            {
                Grid grid = sender as Grid;
                if (grid != null)
                {
                    PasswordEntry entry = grid.DataContext as PasswordEntry;
                    if (entry != null)
                    {
                        CopyToClipboard(entry.Password);
                        ShowCopyFeedback("Mot de passe copié dans le presse-papiers !");
                    }
                }
            }
        }

        private void GeneratedPassword_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            TextBox textBox = sender as TextBox;
            if (textBox != null && !string.IsNullOrEmpty(textBox.Text))
            {
                CopyToClipboard(textBox.Text);
                ShowCopyFeedback("Mot de passe généré copié dans le presse-papiers !");
            }
        }

        private void CopyToClipboard(string text)
        {
            try
            {
                Clipboard.SetText(text);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Erreur lors de la copie : {ex.Message}");
            }
        }

        private void ShowCopyFeedback(string message)
        {
            txtCopyFeedback.Text = message;
            popupCopyFeedback.IsOpen = true;

            System.Threading.Tasks.Task.Delay(2500).ContinueWith(_ =>
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    popupCopyFeedback.IsOpen = false;
                });
            });
        }

        private void DataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {

        }
    }
}
