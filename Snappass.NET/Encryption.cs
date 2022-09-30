using NuGet.Protocol;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Snappass
{
    public class Encryption
    {
        private static readonly char tokenSeparator = '~';

        public static (string encryptedPassword, string encryptionKey) Encrypt(string password)
        {

            var key = new byte[32];
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];
            var plaintextBytes = Encoding.UTF8.GetBytes(password);
            var ciphertext = new byte[plaintextBytes.Length];

            RandomNumberGenerator.Fill(key);
            RandomNumberGenerator.Fill(nonce);

            using var aes = new AesGcm(key);

            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

            return (Convert.ToBase64String(ciphertext), CombineBytesToString(key, nonce, tag));
        }

        public static string Decrypt(string encryptedPassword, string encryptionKey)
        {
            (var key, var nonce, var tag) = SplitStringToBytes(encryptionKey);

            var ciphertext = Convert.FromBase64String(encryptedPassword);

            using (var aes = new AesGcm(key))
            {
                var plaintextBytes = new byte[ciphertext.Length];
                aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);
                return Encoding.UTF8.GetString(plaintextBytes);
            }
        }

        public static string CombineBytesToString(byte[] key, byte[] nonce, byte[] tag)
        {
            byte[] bytes = new byte[key.Length+nonce.Length+tag.Length];

            Buffer.BlockCopy(key, 0, bytes, 0, key.Length);
            Buffer.BlockCopy(nonce, 0, bytes, key.Length, nonce.Length);
            Buffer.BlockCopy(tag, 0, bytes, key.Length+nonce.Length, tag.Length);

            return Convert.ToBase64String(bytes);
        }

        public static (byte[] key, byte[] nonce, byte[] tag) SplitStringToBytes(string bytestring)
        {
            byte[] bytes = Convert.FromBase64String(bytestring);

            var key = bytes.Take(32).ToArray();
            var nonce = bytes.Skip(32).Take(AesGcm.NonceByteSizes.MaxSize).ToArray();
            var tag = bytes.Skip(32 + AesGcm.NonceByteSizes.MaxSize).Take(AesGcm.TagByteSizes.MaxSize).ToArray();

            return (key, nonce, tag);
        }

        public static (string storageKey, string decryptionKey) ParseToken(string token)
        { 
            var tokenFragments = token.Split(tokenSeparator, 2);
            var storageKey = tokenFragments[0];
            var decryptionKey = string.Empty;

            if (tokenFragments.Length > 1)
                decryptionKey = HttpUtility.UrlDecode(tokenFragments[1]).Replace("-","+");

            return (storageKey, decryptionKey);
        }
        public static string CreateToken(string storageKey, string encryptionKey)
        {
            var token = string.Join(tokenSeparator, storageKey, HttpUtility.UrlEncode(encryptionKey.Replace("+","-")));

            return token;
        }
    }
}
