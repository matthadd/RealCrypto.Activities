using System;
using System.Collections.Generic;
using System.Text;
using System.Activities;
using System.ComponentModel;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

namespace RealCrypto.Activities
{
    public class AES256ECBPKCS1
    {
        public static string EncryptBySymmetricKey(string data, string key)
        {
            try
            {
                byte[] dataToEncrypt = Convert.FromBase64String(data);
                var keyBytes = Convert.FromBase64String(key);
                AesManaged tdes = new AesManaged();
                tdes.KeySize = 256;
                tdes.BlockSize = 128;
                tdes.Key = keyBytes;
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;
                ICryptoTransform encrypt__1 = tdes.CreateEncryptor();
                byte[] deCipher = encrypt__1.TransformFinalBlock(dataToEncrypt, 0, dataToEncrypt.Length);
                tdes.Clear();
                string EK_result = Convert.ToBase64String(deCipher);
                return EK_result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        public static string DecryptBySymmetricKey(string encryptedText, string key)
        {
            try
            {
                byte[] dataToDecrypt = Convert.FromBase64String(encryptedText);
                var keyBytes = Convert.FromBase64String(key);
                AesManaged tdes = new AesManaged();
                tdes.KeySize = 256;
                tdes.BlockSize = 128;
                tdes.Key = keyBytes;
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;
                ICryptoTransform decrypt__1 = tdes.CreateDecryptor();
                byte[] deCipher = decrypt__1.TransformFinalBlock(dataToDecrypt, 0, dataToDecrypt.Length);
                tdes.Clear();
                string EK_result = Convert.ToBase64String(deCipher);
                return EK_result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
    }

        public class RealCryptoAES256ECBPKCS1 : CodeActivity
        {
            [Category("Input")] public InArgument<string> Data { get; set; }
            [Category("Input")] public InArgument<string> Key { get; set; }
            [Category("Input")] public InArgument<Boolean> doEncrypt { get; set; }

            [Category("Output")] public OutArgument<string> Cipherresult { get; set; }

            protected override void Execute(CodeActivityContext context)
            {
                var data = Data.Get(context);
                var key = Key.Get(context);
                string cipherresult = "";

                if (doEncrypt.Get(context))
                {
                    cipherresult = AES256ECBPKCS1.EncryptBySymmetricKey(data, key);
                }
                else
                {
                    cipherresult = AES256ECBPKCS1.DecryptBySymmetricKey(data, key);
                }
                Cipherresult.Set(context, cipherresult);

            }
        }
    }

