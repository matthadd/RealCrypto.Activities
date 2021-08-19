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
    public class RSAPKCS1
    {
        public static string Encrypt(string data, string key)
        {
            byte[] keyBytes =
           Convert.FromBase64String(key);
            AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
            RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            RSAParameters rsaParameters = new RSAParameters();
            rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
            rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);
            byte[] plaintext = Encoding.UTF8.GetBytes(data);
            byte[] ciphertext = rsa.Encrypt(plaintext, false);
            string cipherresult = Convert.ToBase64String(ciphertext);
            return cipherresult;
        }
        public class RealCryptoRSAPKCS1 : CodeActivity
        {
            [Category("Input")] public InArgument<string> Data { get; set; }
            [Category("Input")] public InArgument<string> Pubkey { get; set; }
            [Category("Output")] public OutArgument<string> Cipherresult { get; set; }

            protected override void Execute(CodeActivityContext context)
            {
                var data = Data.Get(context);
                var pubkey = Pubkey.Get(context);

                string cipherresult = RSAPKCS1.Encrypt(data, pubkey);
                Cipherresult.Set(context, cipherresult);
            }
        }
    }
}

