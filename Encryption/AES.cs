using Penguin.Security.Objects;
using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Penguin.Security.Encryption
{
    /// <summary>
    /// A class used for encrypting/decrypting data with AES algorithms
    /// </summary>
    public class AES
    {
        #region Constructors

        /// <summary>
        /// Creates a new instance of the AES encryptor with the specified salt
        /// </summary>
        /// <param name="salt">The salt to be used when encrypting/decrypting</param>
        public AES(string salt)
        {
            _salt = Encoding.ASCII.GetBytes(salt);
        }

        /// <summary>
        /// Creates a new instance of the AES encryptor with the specified salt
        /// </summary>
        /// <param name="salt">The salt to be used when encrypting/decrypting</param>
        public AES(byte[] salt)
        {
            _salt = salt;
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Decrypts a byte array
        /// </summary>
        /// <param name="cryptBytes">The byte array to decrypt</param>
        /// <param name="password">The password to be used for decryption</param>
        /// <param name="saltBytes">The salt bytes to be used on the decryption</param>
        /// <returns>A decrypted byte array</returns>
        public static byte[] AESDecryptBytes(byte[] cryptBytes, SecureString password, byte[] saltBytes)
        {
            if (cryptBytes is null)
            {
                throw new ArgumentNullException(nameof(cryptBytes));
            }

            byte[] clearBytes = null;

            using (SecureStringBytes secureStringBytes = new(password))
            {
                // create a key from the password and salt, use 32K iterations
                using Rfc2898DeriveBytes key = new(secureStringBytes.GetBytes(), saltBytes, 32768);
                using Aes aes = new AesManaged();
                // set the key size to 256
                aes.KeySize = 256;
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);

                using MemoryStream ms = new();
                using (CryptoStream cs = new(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(cryptBytes, 0, cryptBytes.Length);
                    cs.Close();
                }

                clearBytes = ms.ToArray();
            }

            return clearBytes;
        }

        /// <summary>
        /// Encrypts a byte array
        /// </summary>
        /// <param name="clearBytes">The byte array to encrypt</param>
        /// <param name="password">The password to be used for encryption</param>
        /// <param name="saltBytes">The salt bytes to be used on the encryption</param>
        /// <returns>A encrypted byte array</returns>
        public static byte[] AESEncryptBytes(byte[] clearBytes, SecureString password, byte[] saltBytes)
        {
            if (clearBytes is null)
            {
                throw new ArgumentNullException(nameof(clearBytes));
            }

            if (password is null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            if (saltBytes is null)
            {
                throw new ArgumentNullException(nameof(saltBytes));
            }

            byte[] encryptedBytes = null;

            using (SecureStringBytes secureStringBytes = new(password))
            {
                // create a key from the password and salt, use 32K iterations – see note
                using Rfc2898DeriveBytes key = new(secureStringBytes.GetBytes(), saltBytes, 32768);
                // create an AES object
                using Aes aes = new AesManaged();
                // set the key size to 256
                aes.KeySize = 256;
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);
                using MemoryStream ms = new();
                using (CryptoStream cs = new(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(clearBytes, 0, clearBytes.Length);
                    cs.Close();
                }

                encryptedBytes = ms.ToArray();
            }

            return encryptedBytes;
        }

        /// <summary>
        /// Decrypts an AES encrypted string
        /// </summary>
        /// <param name="cipherText">The encrypted string</param>
        /// <param name="sharedSecret">The decryption password</param>
        /// <param name="salt">The byte array to use for the salt</param>
        /// <returns>A decrypted string</returns>
        public static string DecryptStringAES(string cipherText, string sharedSecret, byte[] salt)
        {
            if (string.IsNullOrEmpty(cipherText))
            {
                throw new ArgumentNullException(nameof(cipherText));
            }

            if (string.IsNullOrEmpty(sharedSecret))
            {
                throw new ArgumentNullException(nameof(sharedSecret));
            }

            // Declare the RijndaelManaged object
            // used to decrypt the data.
            RijndaelManaged aesAlg = null;

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            try
            {
                // generate the key from the shared secret and the salt
                using Rfc2898DeriveBytes key = new(sharedSecret, salt);
                // Create the streams used for decryption.
                byte[] bytes = Convert.FromBase64String(cipherText);
                using MemoryStream msDecrypt = new(bytes);
                // Create a RijndaelManaged object
                // with the specified key and IV.
                using (aesAlg = new RijndaelManaged())
                {
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

                    // Get the initialization vector from the encrypted stream
                    aesAlg.IV = ReadByteArray(msDecrypt);

                    // Create a decrytor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
                    using StreamReader Decrypt = new(csDecrypt);
                    // Read the decrypted bytes from the decrypting stream
                    // and place them in a string.
                    plaintext = Decrypt.ReadToEnd();
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                aesAlg.Clear();
            }

            return plaintext;
        }

        /// <summary>
        /// Encrypts a string with AES
        /// </summary>
        /// <param name="plainText">The string to encrypt</param>
        /// <param name="sharedSecret">The decryption password</param>
        /// <param name="salt">The byte array to use for the salt</param>
        /// <returns>An encrypted string</returns>
        [SuppressMessage("Security", "CA5379:Do Not Use Weak Key Derivation Function Algorithm", Justification = "<Pending>")]
        public static string EncryptStringAES(string plainText, string sharedSecret, byte[] salt)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException(nameof(plainText));
            }

            if (string.IsNullOrEmpty(sharedSecret))
            {
                throw new ArgumentNullException(nameof(sharedSecret));
            }

            string outStr = null;                       // Encrypted string to return
            RijndaelManaged aesAlg = null;              // RijndaelManaged object used to encrypt the data.

            try
            {
                // generate the key from the shared secret and the salt
                using Rfc2898DeriveBytes key = new(sharedSecret, salt);
                // Create a RijndaelManaged object
                using (aesAlg = new RijndaelManaged())
                {
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for encryption.
                    using MemoryStream msEncrypt = new();
                    // prepend the IV
                    msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                    msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                    using (CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using StreamWriter Encrypt = new(csEncrypt);
                        // Write all data to the stream.
                        Encrypt.Write(plainText);
                    }

                    outStr = Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                aesAlg.Clear();
            }

            // Return the encrypted bytes from the memory stream.
            return outStr;
        }

        /// <summary>
        /// Decrypts a byte array
        /// </summary>
        /// <param name="cryptBytes">The byte array to decrypt</param>
        /// <param name="password">The password to be used for decryption</param>
        /// <returns>A decrypted byte array</returns>
        public byte[] AESDecryptBytes(byte[] cryptBytes, SecureString password)
        {
            return AESEncryptBytes(cryptBytes, password, _salt);
        }

        /// <summary>
        /// Encrypts a byte array
        /// </summary>
        /// <param name="clearBytes">The byte array to encrypt</param>
        /// <param name="password">The password to be used for encryption</param>
        /// <returns>A encrypted byte array</returns>
        public byte[] AESEncryptBytes(byte[] clearBytes, SecureString password)
        {
            return AESEncryptBytes(clearBytes, password, _salt);
        }

        /// <summary>
        /// Decrypts an AES encrypted string
        /// </summary>
        /// <param name="cipherText">The encrypted string</param>
        /// <param name="sharedSecret">The decryption password</param>
        /// <returns>A decrypted string</returns>
        public string DecryptStringAES(string cipherText, string sharedSecret)
        {
            return DecryptStringAES(cipherText, sharedSecret, _salt);
        }

        /// <summary>
        /// Encrypts a string with AES
        /// </summary>
        /// <param name="plainText">The string to encrypt</param>
        /// <param name="sharedSecret">The decryption password</param>
        /// <returns>An encrypted string</returns>
        public string EncryptStringAES(string plainText, string sharedSecret)
        {
            return EncryptStringAES(plainText, sharedSecret, _salt);
        }

        #endregion Methods

        #region Properties

        private readonly byte[] _salt;

        #endregion Properties

        private static byte[] ReadByteArray(Stream s)
        {
            byte[] rawLength = new byte[sizeof(int)];
            if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array");
            }

            byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
            return s.Read(buffer, 0, buffer.Length) != buffer.Length ? throw new SystemException("Did not read byte array properly") : buffer;
        }
    }
}