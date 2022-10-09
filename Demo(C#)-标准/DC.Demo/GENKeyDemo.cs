using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Collections;
using System.Text;

namespace DC.Demo
{
    /// <summary>
    /// 直联上传密钥生成样例，仅供参考，用户私钥请妥善保管，用户公钥以及加密后用户对称密钥在网银上上传， 用户对称密钥为16长度字符串，用户可自己随机生成，saas厂商针对不同用户请使用不同密钥串，如有疑问请联系对接人员。
    /// </summary>
    class GENKeyDemo
    {
        public static string SM2_PUBKEY_ST = "BNsIe9U0x8IeSe4h/dxUzVEz9pie0hDSfMRINRXc7s1UIXfkExnYECF4QqJ2SnHxLv3z/99gsfDQrQ6dzN5lZj0=";
        public static string SM2_PUBKEY_TEST = "BNsIe9U0x8IeSe4h/dxUzVEz9pie0hDSfMRINRXc7s1UIXfkExnYECF4QqJ2SnHxLv3z/99gsfDQrQ6dzN5lZj0=";

        public static string SM2_PUBKEY_PRO = "BEynMEZOjNpwZIiD9jXtZSGr3Ecpwn7r+m+wtafXHb6VIZTnugfuxhcKASq3hX+KX9JlHODDl9/RDKQv4XLOFak=";

        // 用户对称密钥,长度为16的随机字符串 取值建议 [0-9,a-z,A-Z]
        public static string USER_KEY = "0123456789qazwsx";

        public static string SOURCES = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890";

        static void Main2(string[] args)
        {

            Hashtable keypair = CMBSM2KeyGen();
            byte[] publickey = (byte[])keypair["publickey"];
            byte[] privatekey = (byte[])keypair["privatekey"];
            Console.WriteLine("用户公钥: " + Convert.ToBase64String(publickey));
            Console.WriteLine("用户私钥: " + Convert.ToBase64String(privatekey));
            try
            {
                string sm4key = GenRandomString(new Random(), SOURCES, 16);
                Console.WriteLine("用户对称密钥: " + sm4key);
                string sm2EnKey = Convert.ToBase64String(CMBSM2Encrypt(Convert.FromBase64String(SM2_PUBKEY_TEST), Encoding.UTF8.GetBytes(sm4key)));
                Console.WriteLine("加密后用户对称密钥: " + sm2EnKey);
                Console.Read();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Console.Read();
            }

        }

        public static string GenRandomString(Random random, string characters, int len)
        {
            char[] text = new char[len];
            for (int i = 0; i < len; i++)
            {
                text[i] = characters[random.Next(characters.Length)];
            }
            return new string(text);
        }

        public static Hashtable CMBSM2KeyGen()
        {
            ECDomainParameters domainParameters = getECDomainParameters();
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            ECKeyGenerationParameters parameters = new ECKeyGenerationParameters(domainParameters, new SecureRandom());
            generator.Init(parameters);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters)keyPair.Public;
            ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters)keyPair.Private;
            Hashtable map = new Hashtable();
            map.Add("publickey", publicKeyParameters.Q.GetEncoded(false));
            map.Add("privatekey", Format(privateKeyParameters.D.ToByteArray()));
            return map;
        }

        private static Object Format(byte[] value)
        {
            if (value.Length == 32)
            {
                return value;
            }
            byte[] bytes = new byte[32];
            if (value.Length > 32)
            {
                Array.Copy(value, value.Length - 32, bytes, 0, 32);
            }
            else
            {
                Array.Copy(value, 0, bytes, 32 - value.Length, value.Length);
            }
            return bytes;
        }

        private static ECDomainParameters getECDomainParameters()
        {
            X9ECParameters spec = ECNamedCurveTable.GetByName("sm2p256v1");
            return new ECDomainParameters(spec.Curve, spec.G, spec.N, spec.H, spec.GetSeed());
        }


        // sm2 加密
        public static byte[] CMBSM2Encrypt(byte[] pubkey, byte[] msg)
        {
            ECPublicKeyParameters publicKey = null;
            publicKey = DCCryptor.EncodePublicKey(pubkey);
            SM2Engine engine = new SM2Engine();
            engine.Init(true, new ParametersWithRandom(publicKey, new SecureRandom()));

            byte[] cipherText = engine.ProcessBlock(msg, 0, msg.Length);
            return C1C2C3ToC1C3C2(cipherText);
        }

        private static ECPrivateKeyParameters EncodePrivateKey(byte[] value)
        {
            BigInteger d = new BigInteger(1, value);
            return new ECPrivateKeyParameters(d, getECDomainParameters());
        }

        // sm2 解密
        public static byte[] CMBSM2Decrypt(byte[] privkey, byte[] msg)
        {
            msg = C1C3C2ToC1C2C3(msg);
            ECPrivateKeyParameters privateKey = null;
            privateKey = EncodePrivateKey(privkey);
            SM2Engine engine = new SM2Engine();
            engine.Init(false, privateKey);
            return engine.ProcessBlock(msg, 0, msg.Length);
        }


        private static byte[] C1C2C3ToC1C3C2(byte[] cipherText)
        {
            if (cipherText == null || cipherText.Length < 97)
            {
                throw new Exception("E10406");
            }
            else
            {
                byte[] bytes = new byte[cipherText.Length];
                Array.Copy(cipherText, 0, bytes, 0, 65);
                Array.Copy(cipherText, cipherText.Length - 32, bytes, 65, 32);
                Array.Copy(cipherText, 65, bytes, 97, cipherText.Length - 97);
                return bytes;
            }
        }

        private static byte[] C1C3C2ToC1C2C3(byte[] cipherText)
        {
            if (cipherText == null || cipherText.Length < 97)
            {
                throw new Exception("E10406");
            }
            else
            {
                byte[] bytes = new byte[cipherText.Length];
                Array.Copy(cipherText, 0, bytes, 0, 65);
                Array.Copy(cipherText, 97, bytes, 65, cipherText.Length - 97);
                Array.Copy(cipherText, 65, bytes, cipherText.Length - 32, 32);
                return bytes;
            }
        }
    }

}
