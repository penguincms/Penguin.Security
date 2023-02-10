using System;
using System.Linq;
using System.Text;

namespace Penguin.Security.Encryption
{
    /// <summary>
    /// A Tiny Encryptor
    /// </summary>
    public class TeaEncryptor
    {
        #region Constructors

        /// <summary>
        /// Creates a new instance of the encryptor using the specified bytes as a password
        /// </summary>
        /// <param name="cryptoBytes"></param>
        public TeaEncryptor(byte[] cryptoBytes)
        {
            _cryptBytes = cryptoBytes;
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Decryption using Corrected Block TEA (xxtea) algorithm
        /// </summary>
        /// <param name="encrypted">String to be decrypted</param>
        /// <returns>
        /// - Empty string if the parameter is empty string.
        /// - Null if the Encrypted string is not Base64
        /// - Decrypted text if the parameter is valid
        /// </returns>
        public string Decrypt(string encrypted)
        {
            if (encrypted is null)
            {
                throw new ArgumentNullException(nameof(encrypted));
            }

            if (encrypted.Length == 0)
            { return ""; }
            try
            {
                uint[] v = ToLongs(Convert.FromBase64String(encrypted));
                uint[] k = ToLongs(_cryptBytes);

                if (v.Length == 0)
                {
                    return null;
                }

                uint n = (uint)v.Length,
                       z = v[n - 1],
                       y = v[0],
                       delta = 0x9e3779b9,
                       e,
                       q = 6 + (52 / n),
                       sum = q * delta,
                       p = 0;

                while (sum != 0)
                {
                    e = (sum >> 2) & 3;

                    for (p = n - 1; p > 0; p--)
                    {
                        z = v[p - 1];
                        y = v[p] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
                    }

                    z = v[n - 1];
                    y = v[0] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));

                    sum -= delta;
                }

                string plaintext = _encoding.GetString(ToBytes(v)).TrimEnd('\0');
                return plaintext;
            }
            catch { }
            return null;
        }

        /// <summary>
        /// Encryption using corrected Block TEA (xxtea) algorithm
        /// </summary>
        /// <param name="text">String to be encrypted (multi-byte safe)</param>
        /// <returns></returns>
        public string Encrypt(string text)
        {
            byte[] textBytes = GetByteForEncryption(text);
            // Convert the text into UTF-8 encoding (byte size)
            uint[] v = ToLongs(textBytes);

            // Simply convert first 16 chars of password as key
            uint[] k = ToLongs(_cryptBytes);

            // Use UInt32 as the original is based on 'unsigned long' in C, which is equiv to UInt32 in .Net (and not ulong)
            uint n = (uint)v.Length, z = v[n - 1];

            // Use UInt32 as the original is based on 'unsigned long' in C, which is equiv to UInt32 in .Net (and not ulong)
            uint delta = 0x9e3779b9, e, q = 6 + (52 / n), sum = 0;

            while (q-- > 0)
            {
                sum += delta;
                e = (sum >> 2) & 3;
                uint p;
                uint y;
                for (p = 0; p < (n - 1); p++)
                {
                    y = v[p + 1];
                    z = v[p] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
                }

                y = v[0];
                z = v[n - 1] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
            }

            // Convert to Base64 so that Control characters doesnt break it
            return Convert.ToBase64String(ToBytes(v));
        }

        #endregion Methods

        #region Fields

        private const short MIN_ENCRYPTION_LENGTH = 6;
        private static readonly UTF8Encoding _encoding = new();
        private readonly byte[] _cryptBytes;

        #endregion Fields

        private static byte[] GetByteForEncryption(string text)
        {
            byte[] bytes = _encoding.GetBytes(text);
            if (bytes.Length < MIN_ENCRYPTION_LENGTH)
            {
                byte[] incBytes = Enumerable.Repeat((byte)0, MIN_ENCRYPTION_LENGTH).ToArray();
                Buffer.BlockCopy(bytes, 0, incBytes, 0, bytes.Length);
                bytes = incBytes;
            }
            return bytes;
        }

        /// <summary>
        /// Convert array of longs back to utf-8 byte array
        /// </summary>
        /// <returns></returns>
        private static byte[] ToBytes(uint[] l)
        {
            byte[] b = new byte[l.Length * 4];

            // Split each long value into 4 separate characters (bytes) using the same format as ToLongs()
            for (int i = 0; i < l.Length; i++)
            {
                b[i * 4] = (byte)(l[i] & 0xFF);
                b[(i * 4) + 1] = (byte)(l[i] >> (8 & 0xFF));
                b[(i * 4) + 2] = (byte)(l[i] >> (16 & 0xFF));
                b[(i * 4) + 3] = (byte)(l[i] >> (24 & 0xFF));
            }
            return b;
        }

        /// <summary>
        /// convert utf-8 byte to array of longs, each containing 4 chars to be manipulated
        /// </summary>
        /// <param name="s"></param>
        private static uint[] ToLongs(byte[] s)
        {
            // note chars must be within ISO-8859-1 (with Unicode code-point < 256) to fit 4/long
            uint[] l = new uint[(int)Math.Ceiling((decimal)s.Length / 4)];

            // Create an array of long, each long holding the data of 4 characters, if the last block is less than 4
            // characters in length, fill with ascii null values
            for (int i = 0; i < l.Length; i++)
            {
                // Note: little-endian encoding - endianness is irrelevant as long as it is the same in ToBytes()
                l[i] = s[i * 4] +
                       (((i * 4) + 1) >= s.Length ? (uint)0 << 8 : ((uint)s[(i * 4) + 1] << 8)) +
                       (((i * 4) + 2) >= s.Length ? (uint)0 << 16 : ((uint)s[(i * 4) + 2] << 16)) +
                       (((i * 4) + 3) >= s.Length ? (uint)0 << 24 : ((uint)s[(i * 4) + 3] << 24));
            }

            return l;
        }
    }
}