using Newtonsoft.Json.Linq;
using System;
using System.Collections;
using System.Text;
using System.Web;

namespace DC.Demo
{
    /// <summary>
    ///  国密免前置/SaaS对接示例，本示例仅供参考，不保证各种异常场景运行，请勿直接使用，如有错漏请联系对接人员。运行时，请使用所获取的测试资源替换 用户编号、公私钥、对称密钥、服务商编号等信息。
    /// </summary>
    class SMDemo
    {

        private static string URL = "http://cdctest.cmburl.cn:80/cdcserver/api/v2"; // 银行服务地址(测试)
        private static string bankpubkey = "BNsIe9U0x8IeSe4h/dxUzVEz9pie0hDSfMRINRXc7s1UIXfkExnYECF4QqJ2SnHxLv3z/99gsfDQrQ6dzN5lZj0="; // 银行公钥

        private static string privkey = "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E=";
        private static string sm4key = "VuAzSWQhsoNqzn0K";//"1234567890123456"; // 用户的对称密钥

        private static string ALG_SM = "SM"; // 采用国密算法

        public static string UID = "N003261207"; // 测试的用户编号

        static void Main(string[] args)
        {

            // 组织发送报文
            JObject obj = new JObject();
            JObject req = new JObject();
            JObject body = new JObject();
            JObject head = new JObject();
            head.Add("funcode", "DCLISMOD");
            head.Add("userid", UID);
            head.Add("reqid", DCHelper.GetTime() + "0000001");
            body.Add("buscod", "N02030");
            body.Add("TEST", "中文");
            body.Add("TEST2", "!@#$%^&*()\\\\///");
            body.Add("TEST3", 12345);
            JArray array = new JArray();
            JObject item = new JObject();
            item.Add("arrItem1", "qaz");
            item.Add("arrItem2", 123);
            item.Add("arrItem3", true);
            item.Add("arrItem4", "中文");

            array.Add(item);
            body.Add("TEST4", array);
            req.Add("head", head);
            req.Add("body", body);
            obj.Add("request", req);

            // 请求发送接收
            doProcess(obj);
        }


        private static void doProcess(JObject jObject)
        {
            JObject obj = new JObject();
            // 签名
            obj.Add("sigdat", "__signature_sigdat__");
            obj.Add("sigtim", DCHelper.GetTime());
            jObject.Add("signature", obj);
            string source = DCHelper.SerialJsonOrdered(jObject);
            Console.WriteLine("签名原文: " + source);
            Encoding encoding = Encoding.UTF8;
            byte[] signature1 = DCCryptor.CMBSM2SignWithSM3(GetID_IV(), Convert.FromBase64String(privkey), encoding.GetBytes(source));
            string sigdat1 = Convert.ToBase64String(signature1);
            Console.WriteLine("签名结果: " + sigdat1);
            obj["sigdat"] = sigdat1;

            // SM4-CBC加密
            string plaintxt = jObject.ToString();
            Console.WriteLine("加密前req:  " + plaintxt);
            byte[] enInput = DCCryptor.CMBSM4EncryptWithCBC(encoding.GetBytes(sm4key), GetID_IV(), encoding.GetBytes(plaintxt));
            string req = Convert.ToBase64String(enInput);
            Console.WriteLine("加密后req:  " + req);

            // 发送请求
            Hashtable map = new Hashtable();
            map.Add("UID", UID);
            map.Add("ALG", ALG_SM);
            map.Add("DATA", HttpUtility.UrlEncode(req, encoding));
            map.Add("FUNCODE", "DCLISMOD");
            string res = DCHelper.DoPostForm(URL, map);
            Console.WriteLine("res:  " + res);
            try
            {
                Convert.FromBase64String(res);
            }
            catch (Exception e)
            {
                Console.WriteLine("访问返回错误.");
                Console.ReadKey();
                return;
            }

            // 解密请求
            string resplain = encoding.GetString(DCCryptor.CMBSM4DecryptWithCBC(encoding.GetBytes(sm4key), GetID_IV(), Convert.FromBase64String(res)));
            Console.WriteLine("res decrypt: " + resplain);

            // 验签
            JObject object2 = JObject.Parse(resplain);
            JObject object3 = object2["signature"] as JObject;
            string resSign = (string)object3["sigdat"];
            object3["sigdat"] = "__signature_sigdat__";
            object2["signature"] = object3;
            string resSignSource = DCHelper.SerialJsonOrdered(object2);
            Console.WriteLine("验签原文: " + resSignSource);
            Console.WriteLine("验签签名值: " + resSign);
            bool verify = DCCryptor.CMBSM2VerifyWithSM3(GetID_IV(), Convert.FromBase64String(bankpubkey), encoding.GetBytes(resSignSource), Convert.FromBase64String(resSign));
            Console.WriteLine("验签结果: " + verify);
            Console.ReadKey();
        }

        private static byte[] GetID_IV()
        {
            String uid = UID; // 请替换为实际的用户UID
            String userid = uid + "0000000000000000";
            return Encoding.UTF8.GetBytes(userid.Substring(0, 16));
        }
    }
}
