using Penguin.Security.Encryption;
using Penguin.Security.IO;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Penguin.Security.Objects
{
    /// <summary>
    /// A process used to allow a used to access an encrypted file in a monitored way
    /// </summary>
    [System.ComponentModel.DesignerCategory("Code")]
    public class EncryptionProcess : System.Diagnostics.Process
    {
        #region Properties

        /// <summary>
        /// The source file (encrypted)
        /// </summary>
        public string OriginalFilePath { get; set; }

        /// <summary>
        /// The path to the unencrypted temporary instance being run
        /// </summary>
        public string TempFilePath { get; set; }

        /// <summary>
        /// A file system watcher intended to monitor file access and persist changes back to the original encrypted version
        /// </summary>
        public FileSystemWatcher Watcher { get; set; }

        #endregion Properties

        #region Constructors

        /// <summary>
        /// Creates a new instance of an encrypted proces
        /// </summary>
        /// <param name="password">The file password</param>
        /// <param name="salt">The password salt</param>
        /// <param name="file">The file path of the encrypted file</param>
        public EncryptionProcess(SecureString password, string salt, string file)
        {
            this.Init(password, Encoding.ASCII.GetBytes(salt), file);
        }

        /// <summary>
        /// Creates a new instance of an encrypted proces
        /// </summary>
        /// <param name="password">The file password</param>
        /// <param name="salt">The password salt</param>
        /// <param name="file">The file path of the encrypted file</param>
        public EncryptionProcess(SecureString password, byte[] salt, string file)
        {
            this.Init(password, salt, file);
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Attempts to copy back any changes from the temporary file, and clean up
        /// </summary>
        /// <param name="sender">Unused</param>
        /// <param name="e">Unused</param>
        public void CleanUp(object sender, EventArgs e)
        {
            this.Watcher.Dispose();
            this.Watcher = null;

            while (this.IsLocked())
            {
                System.Threading.Thread.Sleep(100);
            }

            this.UpdateOriginal();
            EncryptedFile.Delete(this.TempFilePath, new Random());
        }

        /// <summary>
        /// Manual method to delete the temporary file used to access the encrypted file
        /// </summary>
        public void CleanUp() => this.CleanUp(null, null);

        /// <summary>
        /// Checks to see if the temporary file is currently being accessed
        /// </summary>
        /// <returns>A bool representing whether or not the temporary file is currently being accessed</returns>
        public bool IsLocked()
        {
            FileStream stream = null;

            try
            {
                stream = new FileInfo(this.TempFilePath).Open(FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException)
            {
                return true;
            }
            finally
            {
                if (stream != null)
                {
                    stream.Close();
                }
            }

            return false;
        }

        /// <summary>
        /// Decrypts the file and attempts to launch a program to access the file
        /// </summary>
        /// <returns>The running process accessing the file</returns>
        public new EncryptionProcess Start()
        {
            File.WriteAllBytes(this.TempFilePath, this.Crypto.AESDecryptBytes(File.ReadAllBytes(this.OriginalFilePath), this.Key));
            this.Watcher.EnableRaisingEvents = true;

            string ext = System.IO.Path.GetExtension(this.TempFilePath); // get extension

            StringBuilder sb = new StringBuilder(500); // buffer for exe file path
            uint size = 500; // buffer size

            /*Get associated app*/
            uint res = AssocQueryString(AssocF.None, AssocStr.Executable, ext, null, sb, ref size);

            if (res != 0)
            {
                this.StartInfo = new ProcessStartInfo(this.TempFilePath); // can't get app, use standard method
            }
            else
            {
                this.StartInfo = new ProcessStartInfo(sb.ToString(), this.TempFilePath);
            }

            this.StartInfo = new System.Diagnostics.ProcessStartInfo(this.TempFilePath);

            base.Start();

            return this;
        }

        #endregion Methods

        #region Enums

        [Flags]
        internal enum AssocF : uint
        {
            None = 0,
            Init_NoRemapCLSID = 0x1,
            Init_ByExeName = 0x2,
            Open_ByExeName = 0x2,
            Init_DefaultToStar = 0x4,
            Init_DefaultToFolder = 0x8,
            NoUserSettings = 0x10,
            NoTruncate = 0x20,
            Verify = 0x40,
            RemapRunDll = 0x80,
            NoFixUps = 0x100,
            IgnoreBaseClass = 0x200,
            Init_IgnoreUnknown = 0x400,
            Init_FixedProgId = 0x800,
            IsProtocol = 0x1000,
            InitForFile = 0x2000
        }

        internal enum AssocStr
        {
            Command = 1,
            Executable,
            FriendlyDocName,
            FriendlyAppName,
            NoOpen,
            ShellNewValue,
            DDECommand,
            DDEIfExec,
            DDEApplication,
            DDETopic,
            InfoTip,
            QuickTip,
            TileInfo,
            ContentType,
            DefaultIcon,
            ShellExtension,
            DropTarget,
            DelegateExecute,
            SupportedUriProtocols,
            Max,
        }

        #endregion Enums

        private AES Crypto { get; set; }

        private SecureString Key { get; set; }

        [DllImport("Shlwapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern uint AssocQueryString(AssocF flags, AssocStr str, string pszAssoc, string pszExtra, [Out] StringBuilder pszOut, ref uint pcchOut);

        private void Init(SecureString password, byte[] salt, string file)
        {
            this.Crypto = new AES(salt);
            this.Key = password;
            this.EnableRaisingEvents = true;
            Exited += this.CleanUp;

            this.OriginalFilePath = file;

            string tempFileDir = Path.Combine(Path.GetTempPath(), "Encrypted");

            if (!Directory.Exists(tempFileDir))
            {
                Directory.CreateDirectory(tempFileDir);
            }

            this.TempFilePath = Path.Combine(tempFileDir, Path.GetRandomFileName() + Path.GetExtension(Path.GetFileNameWithoutExtension(this.OriginalFilePath)));

            FileInfo tempFileInfo = new FileInfo(this.TempFilePath);

            this.Watcher = new FileSystemWatcher
            {
                Path = new FileInfo(this.TempFilePath).Directory.FullName,
                Filter = new FileInfo(this.TempFilePath).Name
            };

            this.Watcher.Changed += this.Watcher_Changed;
        }

        private void UpdateOriginal()
        {
            bool success = false;

            while (!success)
            {
                try
                {
                    File.WriteAllBytes(this.OriginalFilePath, this.Crypto.AESEncryptBytes(File.ReadAllBytes(this.TempFilePath), this.Key));
                    success = true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    Console.WriteLine("Retrying...");
                }

                if (!success)
                {
                    System.Threading.Thread.Sleep(1000);
                }
            }

            Console.WriteLine("Successfully updated file.");
        }

        private void Watcher_Changed(object sender, FileSystemEventArgs e)
        {
            this.Watcher.EnableRaisingEvents = false;
            this.UpdateOriginal();
            this.Watcher.EnableRaisingEvents = true;
        }
    }
}