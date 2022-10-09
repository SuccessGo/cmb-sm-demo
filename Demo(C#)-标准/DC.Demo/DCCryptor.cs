using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using System;

namespace DC.Demo
{
    /// <summary>
    /// 示例代码，仅供参考
    /// </summary>
    class DCCryptor
    {

        public static byte[] CMBSM4EncryptWithCBC(byte[] key, byte[] iv, byte[] input)
        {
            if (key == null || iv == null || input == null)
            {
                throw new Exception("CMBSM4EncryptWithCBC 非法输入");
            }
            return CMBSM4Crypt(key, iv, input, true);
        }

        public static byte[] CMBSM4DecryptWithCBC(byte[] key, byte[] iv, byte[] input)
        {
            if (key == null || iv == null || input == null)
            {
                throw new Exception("CMBSM4DecryptWithCBC 非法输入");
            }
            return CMBSM4Crypt(key, iv, input, false);
        }

        public static byte[] CMBSM2SignWithSM3(byte[] id, byte[] privkey, byte[] msg)
        {
            if (privkey == null || msg == null)
            {
                throw new Exception("CMBSM2SignWithSM3 input error");
            }
            ECPrivateKeyParameters privateKey = EncodePrivateKey(privkey);
            SM2Signer signer = new SM2Signer();
            ParametersWithID parameters = new ParametersWithID(privateKey, id);
            signer.Init(true, parameters);
            signer.BlockUpdate(msg, 0, msg.Length);
            return DecodeDERSignature(signer.GenerateSignature());
        }

        public static bool CMBSM2VerifyWithSM3(byte[] id, byte[] pubkey, byte[] msg, byte[] signature)
        {

            if (pubkey == null || msg == null || signature == null)
            {
                throw new Exception("CMBSM2VerifyWithSM3 input error");
            }
            ECPublicKeyParameters publicKey = EncodePublicKey(pubkey);
            SM2Signer signer = new SM2Signer();
            ParametersWithID parameters = new ParametersWithID(publicKey, id);
            signer.Init(false, parameters);
            signer.BlockUpdate(msg, 0, msg.Length);
            return signer.VerifySignature(EncodeDERSignature(signature));
        }

        private static byte[] CMBSM4Crypt(byte[] keyBytes, byte[] iv, byte[] input, bool forEncrypt)
        {
            KeyParameter key = ParameterUtilities.CreateKeyParameter("SM4", keyBytes);
            ParametersWithIV ivParameterSpec = new ParametersWithIV(key, iv);
            IBufferedCipher cipher = CipherUtilities.GetCipher("SM4/CBC/PKCS7Padding");
            cipher.Init(forEncrypt, ivParameterSpec);
            return cipher.DoFinal(input);
        }

        private static ECPrivateKeyParameters EncodePrivateKey(byte[] value)
        {
            BigInteger d = new BigInteger(1, value);
            X9ECParameters spec = ECNamedCurveTable.GetByName("sm2p256v1");
            ECDomainParameters ecParameters = new ECDomainParameters(spec.Curve, spec.G, spec.N, spec.H, spec.GetSeed());
            return new ECPrivateKeyParameters(d, ecParameters);
        }

        public static ECPublicKeyParameters EncodePublicKey(byte[] value)
        {
            byte[] x = new byte[32];
            byte[] y = new byte[32];
            Array.Copy(value, 1, x, 0, 32);
            Array.Copy(value, 33, y, 0, 32);
            BigInteger X = new BigInteger(1, x);
            BigInteger Y = new BigInteger(1, y);
            X9ECParameters spec = ECNamedCurveTable.GetByName("sm2p256v1");
            ECPoint Q = spec.Curve.CreatePoint(X, Y);
            ECDomainParameters ecParameters = new ECDomainParameters(spec.Curve, spec.G, spec.N, spec.H, spec.GetSeed());
            return new ECPublicKeyParameters(Q, ecParameters);
        }

        private static byte[] DecodeDERSignature(byte[] signature)
        {
            Asn1InputStream stream = new Asn1InputStream(signature);
            Asn1Sequence primitive = (Asn1Sequence)stream.ReadObject();
            System.Collections.IEnumerator enumeration = primitive.GetEnumerator();
            enumeration.MoveNext();
            BigInteger R = ((DerInteger)enumeration.Current).Value;
            enumeration.MoveNext();
            BigInteger S = ((DerInteger)enumeration.Current).Value;
            byte[] bytes = new byte[64];
            byte[] r = Format(R.ToByteArray());
            byte[] s = Format(S.ToByteArray());
            Array.Copy(r, 0, bytes, 0, 32);
            Array.Copy(s, 0, bytes, 32, 32);
            return bytes;
        }

        private static byte[] EncodeDERSignature(byte[] signature)
        {
            byte[] r = new byte[32];
            byte[] s = new byte[32];
            Array.Copy(signature, 0, r, 0, 32);
            Array.Copy(signature, 32, s, 0, 32);
            Asn1EncodableVector vector = new Asn1EncodableVector();
            vector.Add(new DerInteger(new BigInteger(1, r)));
            vector.Add(new DerInteger(new BigInteger(1, s)));
            return (new DerSequence(vector)).GetEncoded();
        }

        private static byte[] Format(byte[] value)
        {
            if (value.Length == 32)
            {
                return value;
            }
            else
            {
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
        }
    }
}
