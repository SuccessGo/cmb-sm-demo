package dc.demo;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * 直联上传密钥生成样例，仅供参考，用户私钥请妥善保管，用户公钥以及加密后用户对称密钥在网银上上传， 用户对称密钥为16长度字符串，用户可自己随机生成，saas厂商针对不同用户请使用不同密钥串，如有疑问请联系对接人员。
 */
public class GENKeyDemo {

    public static String SM2_PUBKEY_ST = "BNsIe9U0x8IeSe4h/dxUzVEz9pie0hDSfMRINRXc7s1UIXfkExnYECF4QqJ2SnHxLv3z/99gsfDQrQ6dzN5lZj0=";
    public static String SM2_PUBKEY_TEST = "BNsIe9U0x8IeSe4h/dxUzVEz9pie0hDSfMRINRXc7s1UIXfkExnYECF4QqJ2SnHxLv3z/99gsfDQrQ6dzN5lZj0=";

    public static String SM2_PUBKEY_PRO = "BEynMEZOjNpwZIiD9jXtZSGr3Ecpwn7r+m+wtafXHb6VIZTnugfuxhcKASq3hX+KX9JlHODDl9/RDKQv4XLOFak=";

    // 用户对称密钥,长度为16的随机字符串 取值建议 [0-9,a-z,A-Z]
    public static String USER_KEY = "0123456789qazwsx";

    public static final String SOURCES = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890";

    public static void main(String[] args) {

        Map<String, byte[]> keypair = CMBSM2KeyGen();
        byte[] publickey = keypair.get("publickey");
        byte[] privatekey = keypair.get("privatekey");
        System.out.println("用户公钥: " + Base64.getEncoder().encodeToString(publickey));
        System.out.println("用户私钥: " + Base64.getEncoder().encodeToString(privatekey));
        try {

            String sm4key = genRandomString(new Random(), SOURCES, 16);
            System.out.println("用户对称密钥: " + sm4key);
            String sm2EnKey = Base64.getEncoder().encodeToString(CMBSM2Encrypt(Base64.getDecoder().decode(SM2_PUBKEY_TEST), sm4key.getBytes("utf-8")));
            System.out.println("加密后用户对称密钥: " + sm2EnKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成随机字符串 [0-9,a-z,A-Z]
     * 
     * @param random
     * @param characters
     * @param len
     * @return
     */
    public static String genRandomString(Random random, String characters, int len) {
        char[] text = new char[len];
        for (int i = 0; i < len; i++) {
            text[i] = characters.charAt(random.nextInt(characters.length()));
        }
        return new String(text);
    }

    /**
     * 生成国密密钥对
     * 
     * @return
     */
    public static Map<String, byte[]> CMBSM2KeyGen() {
        ECDomainParameters domainParameters = getECDomainParameters();
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters parameters = new ECKeyGenerationParameters(domainParameters, new SecureRandom());
        generator.init(parameters);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters) keyPair.getPublic();
        ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters) keyPair.getPrivate();
        Map<String, byte[]> map = new HashMap<>();
        map.put("publickey", publicKeyParameters.getQ().getEncoded(false));
        map.put("privatekey", format(privateKeyParameters.getD().toByteArray()));
        return map;
    }

    private static byte[] format(byte[] value) {
        if (value.length == 32) {
            return value;
        }
        byte bytes[] = new byte[32];
        if (value.length > 32) {
            System.arraycopy(value, value.length - 32, bytes, 0, 32);
        } else {
            System.arraycopy(value, 0, bytes, 32 - value.length, value.length);
        }
        return bytes;
    }

    private static ECDomainParameters getECDomainParameters() {
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        return new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
    }

    // sm2 加密
    public static byte[] CMBSM2Encrypt(byte pubkey[], byte msg[]) throws Exception {
        ECPublicKeyParameters publicKey = null;
        publicKey = DCCryptor.encodePublicKey(pubkey);
        SM2Engine engine = new SM2Engine();
        engine.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));

        byte cipherText[] = engine.processBlock(msg, 0, msg.length);
        return C1C2C3ToC1C3C2(cipherText);
    }

    // sm2 解密
    public static byte[] CMBSM2Decrypt(byte privkey[], byte msg[]) throws Exception {
        msg = C1C3C2ToC1C2C3(msg);
        ECPrivateKeyParameters privateKey = null;
        privateKey = encodePrivateKey(privkey);
        SM2Engine engine = new SM2Engine();
        engine.init(false, privateKey);
        return engine.processBlock(msg, 0, msg.length);
    }

    private static ECPrivateKeyParameters encodePrivateKey(byte value[]) {
        BigInteger d = new BigInteger(1, value);
        return new ECPrivateKeyParameters(d, getECDomainParameters());
    }

    private static byte[] C1C2C3ToC1C3C2(byte cipherText[]) throws Exception {
        if (cipherText == null || cipherText.length < 97) {
            throw new Exception("E10406");
        } else {
            byte bytes[] = new byte[cipherText.length];
            System.arraycopy(cipherText, 0, bytes, 0, 65);
            System.arraycopy(cipherText, cipherText.length - 32, bytes, 65, 32);
            System.arraycopy(cipherText, 65, bytes, 97, cipherText.length - 97);
            return bytes;
        }
    }

    private static byte[] C1C3C2ToC1C2C3(byte cipherText[]) throws Exception {
        if (cipherText == null || cipherText.length < 97) {
            throw new Exception("E10406");
        } else {
            byte bytes[] = new byte[cipherText.length];
            System.arraycopy(cipherText, 0, bytes, 0, 65);
            System.arraycopy(cipherText, 97, bytes, 65, cipherText.length - 97);
            System.arraycopy(cipherText, 65, bytes, cipherText.length - 32, 32);
            return bytes;
        }
    }
}
