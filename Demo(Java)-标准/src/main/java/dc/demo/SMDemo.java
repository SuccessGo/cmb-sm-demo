package dc.demo;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * 国密免前置/SaaS对接示例，本示例仅供参考，不保证各种异常场景运行，请勿直接使用，如有错漏请联系对接人员。运行时，请使用所获取的测试资源替换 用户编号、公私钥、对称密钥、服务商编号等信息。
 */
public class SMDemo {

    private static String URL = "http://cdctest.cmburl.cn:80/cdcserver/api/v2"; // 银行服务地址(测试)
    private static String bankpubkey = "BNsIe9U0x8IeSe4h/dxUzVEz9pie0hDSfMRINRXc7s1UIXfkExnYECF4QqJ2SnHxLv3z/99gsfDQrQ6dzN5lZj0="; // 银行公钥

    private static String privkey = "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E=";
    private static String sm4key = "VuAzSWQhsoNqzn0K";//"1234567890123456"; // 用户的对称密钥

    private static Base64.Encoder encoder = Base64.getEncoder();
    private static Base64.Decoder decoder = Base64.getDecoder();

    private static final String ALG_SM = "SM"; // 采用国密算法

    private static String UID = "N003261207"; // 测试的用户编号
    
    public static void main(String[] args) throws Exception {
        // 组织发送报文
        JsonObject obj = new JsonObject();
        JsonObject req = new JsonObject();
        JsonObject body = new JsonObject();
        JsonObject head = new JsonObject();
        head.addProperty("funcode", "DCLISMOD");
        head.addProperty("userid", UID);
        head.addProperty("reqid", DCHelper.getTime() + "0000001");
        body.addProperty("buscod", "N02030");
        body.addProperty("TEST", "中文");
        body.addProperty("TEST2", "!@#$%^&*()\\\\///");
        body.addProperty("TEST3", 12345);
        JsonArray array = new JsonArray();
        JsonObject item = new JsonObject();
        item.addProperty("arrItem1", "qaz");
        item.addProperty("arrItem2", 123);
        item.addProperty("arrItem3", true);
        item.addProperty("arrItem4", "中文");

        array.add(item);
        body.add("TEST4", array);
        req.add("head", head);
        req.add("body", body);
        obj.add("request", req);

        // 请求发送接收
        doProcess(obj);
    }

    private static void doProcess(JsonObject jObject) throws Exception {
        JsonObject object = new JsonObject();
        // 签名
        object.addProperty("sigdat", "__signature_sigdat__");
        object.addProperty("sigtim", DCHelper.getTime());
        jObject.add("signature", object);
        String source = DCHelper.serialJsonOrdered(jObject);
        System.out.println("签名原文: " + source);
        byte[] signature1 = DCCryptor.CMBSM2SignWithSM3(getID_IV(), decoder.decode(privkey), source.getBytes(StandardCharsets.UTF_8));
        String sigdat1 = new String(encoder.encode(signature1));
        System.out.println("签名结果: " + sigdat1);
        object.addProperty("sigdat", sigdat1);

        // SM4-CBC加密
        String plaintxt = jObject.toString();
        System.out.println("加密前req:  " + plaintxt);
        byte[] enInput = DCCryptor.CMBSM4EncryptWithCBC(sm4key.getBytes(), getID_IV(), plaintxt.getBytes(StandardCharsets.UTF_8));

        String req = new String(encoder.encode(enInput));
        System.out.println("加密后req:  " + req);

        // 发送请求
        HashMap<String, String> map = new HashMap<>();
        map.put("UID", UID);
        map.put("ALG", ALG_SM);
        map.put("DATA", URLEncoder.encode(req, "utf-8"));
        map.put("FUNCODE", "DCLISMOD");
        String res = DCHelper.doPostForm(URL, map);
        System.out.println("res:  " + res);
        try {
            decoder.decode(res);
        } catch (Exception e) {
            System.err.println("访问返回错误.");
            return;
        }

        // 解密请求
        String resplain = new String(DCCryptor.CMBSM4DecryptWithCBC(sm4key.getBytes(), getID_IV(), decoder.decode(res)), StandardCharsets.UTF_8);
        System.out.println("res decrypt: " + resplain);

        // 验签
        JsonObject object2 = new GsonBuilder().create().fromJson(resplain, JsonObject.class);
        JsonObject object3 = object2.getAsJsonObject("signature");
        String resSign = object3.get("sigdat").getAsString();
        object3.addProperty("sigdat", "__signature_sigdat__");
        object2.add("signature", object3);
        String resSignSource = DCHelper.serialJsonOrdered(object2);
        System.out.println("验签原文: " + resSignSource);
        System.out.println("验签签名值: " + resSign);
        boolean verify = DCCryptor.CMBSM2VerifyWithSM3(getID_IV(), decoder.decode(bankpubkey), resSignSource.getBytes(StandardCharsets.UTF_8), decoder.decode(resSign));
        System.out.println("验签结果: " + verify);
    }

    private static byte[] getID_IV() {
        String uid = UID; // 请替换为实际的用户UID
        String userid = uid + "0000000000000000";
        return userid.substring(0, 16).getBytes();
    }

}
