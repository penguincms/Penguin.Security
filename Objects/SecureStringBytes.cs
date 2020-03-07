using System;
using System.Runtime.InteropServices;
using System.Security;

namespace Penguin.Security.Objects
{
    /// <summary>
    /// A class used to access a byte array representation of a secure string
    /// </summary>
    public sealed class SecureStringBytes : IDisposable
    {
        #region Constructors

        /// <summary>
        /// Creates a new holder for this SecureStringBytes
        /// </summary>
        /// <param name="secureString">The source secure string</param>
        public SecureStringBytes(SecureString secureString)
        {
            this.secureString = secureString ?? throw new ArgumentNullException(nameof(secureString));
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Clears the bytes out of memory
        /// </summary>
        public void Clear()
        {
            if (this.bytes != null)
            {
                for (int i = 0; i < this.bytes.Length; i++)
                {
                    this.bytes[i] = 0;
                }

                this.bytes = null;
            }
        }

        /// <summary>
        /// Calls the clear function to flush out the memory used by this object
        /// </summary>
        public void Dispose()
        {
            this.Clear();
        }

        /// <summary>
        /// Gets a byte array representing this secure string
        /// </summary>
        /// <returns>A byte array representing this secure string</returns>
        public byte[] GetBytes()
        {
            if (this.bytes == null)
            {
                this.bytes = ConvertSecureStringToBytes(this.secureString);
            }

            return this.bytes;
        }

        #endregion Methods

        #region Fields

        private byte[] bytes;
        private readonly SecureString secureString;

        #endregion Fields

        private static byte[] ConvertSecureStringToBytes(SecureString secureString)
        {
            byte[] result = new byte[secureString.Length * 2];
            IntPtr valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                for (int i = 0; i < secureString.Length; i++)
                {
                    result[i] = Marshal.ReadByte(valuePtr, i * 2);
                    result[i + 1] = Marshal.ReadByte(valuePtr, (i * 2) + 1);
                }
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }

            return result;
        }
    }
}