using Penguin.Security.Encryption;
using System;
using System.IO;
using System.Security;

namespace Penguin.Security.IO
{
    /// <summary>
    /// A class used to hold and access an instance of an encrypted file
    /// </summary>
    public class EncryptedFile
    {
        #region Constructors

        /// <summary>
        /// Creates a new encrypted file instance
        /// </summary>
        /// <param name="file">A fileinfo representing the file</param>
        /// <param name="salt">The salt used to access the file</param>
        public EncryptedFile(FileInfo file, string salt)
        {
            this.TargetFile = file;
            this.Crypto = new AES(salt);
        }

        /// <summary>
        /// Creates a new encrypted file instance
        /// </summary>
        /// <param name="filePath">The path to the file</param>
        /// <param name="salt">The salt used to access the file</param>
        public EncryptedFile(string filePath, string salt)
        {
            this.TargetFile = new FileInfo(filePath);
            this.Crypto = new AES(salt);
        }

        /// <summary>
        /// Creates a new encrypted file instance
        /// </summary>
        /// <param name="file">A fileinfo representing the file</param>
        /// <param name="salt">The salt used to access the file</param>
        public EncryptedFile(FileInfo file, byte[] salt)
        {
            this.TargetFile = file;
            this.Crypto = new AES(salt);
        }

        /// <summary>
        /// Creates a new encrypted file instance
        /// </summary>
        /// <param name="filePath">The path to the file</param>
        /// <param name="salt">The salt used to access the file</param>
        public EncryptedFile(string filePath, byte[] salt)
        {
            this.TargetFile = new FileInfo(filePath);
            this.Crypto = new AES(salt);
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Flushes a file with random bytes and then deletes it
        /// </summary>
        /// <param name="filePath">The file to delete</param>
        /// <param name="r">An optional Random to be used to flush the file before deleting</param>
        public static void Delete(string filePath, Random r = null)
        {
            r = r ?? new Random();

            byte[] randomBytes = new byte[new FileInfo(filePath).Length];
            r.NextBytes(randomBytes);

            File.WriteAllBytes(filePath, randomBytes);
            File.Delete(filePath);
        }

        /// <summary>
        /// Flushes and deletes this file instance
        /// </summary>
        public void Delete()
        {
            Delete(this.TargetFile.FullName, Random);
        }

        /// <summary>
        /// Decrypts the file and reads back a byte array
        /// </summary>
        /// <param name="password">The password for the file</param>
        /// <returns>A decrypted byte array representing the file contents</returns>
        public byte[] ReadAllBytes(SecureString password) => this.Crypto.AESDecryptBytes(File.ReadAllBytes(this.TargetFile.FullName), password);

        /// <summary>
        /// Encrypts a byte array and writes it back to the file
        /// </summary>
        /// <param name="bytes">The byte array to write</param>
        /// <param name="password">The password to use to encrypt the file contents</param>
        public void WriteAllBytes(byte[] bytes, SecureString password) => File.WriteAllBytes(this.TargetFile.FullName, this.Crypto.AESEncryptBytes(bytes, password));

        #endregion Methods

        #region Properties

        private AES Crypto { get; set; }

        private Random Random { get; set; } = new Random();

        private FileInfo TargetFile { get; set; }

        #endregion Properties
    }
}