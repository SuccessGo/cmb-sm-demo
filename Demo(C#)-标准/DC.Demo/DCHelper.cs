using Newtonsoft.Json.Linq;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;

namespace DC.Demo
{
    /// <summary>
    /// 示例代码，仅供参考
    /// </summary>
    class DCHelper
    {

        public static string SerialJsonOrdered(JObject json)
        {
            List<string> keyList = new List<string>();
            foreach (var x in json)
            {
                keyList.Add(x.Key);
            }
            string[] keyArray = keyList.ToArray();
            Array.Sort(keyArray, string.CompareOrdinal);
            StringBuilder appender = new StringBuilder();
            appender.Append("{");
            bool isFirstEle = true;
            foreach (var key in keyArray)
            {
                if (!isFirstEle)
                {
                    appender.Append(",");
                }
                Object val = json[key];
                if (val is JObject)
                {
                    appender.Append("\"").Append(key).Append("\":");
                    appender.Append(SerialJsonOrdered((JObject)val));
                }
                else if (val is JArray)
                {
                    JArray jarray = (JArray)val;
                    appender.Append("\"").Append(key).Append("\":[");
                    bool isFirstArrEle = true;
                    for (int i = 0; i < jarray.Count; i++)
                    {
                        if (!isFirstArrEle)
                        {
                            appender.Append(",");
                        }
                        Object obj = jarray[i];
                        if (obj is JObject)
                        {
                            appender.Append(SerialJsonOrdered((JObject)obj));
                        }
                        else
                        {
                            appender.Append(obj.ToString());
                        }
                        isFirstArrEle = false;
                    }
                    appender.Append("]");
                }
                else if(((JToken)val).Type == JTokenType.String)
                {
                    string value = val.ToString();
                    appender.Append("\"").Append(key).Append("\":").Append("\"").Append(value.Replace("\\", "\\\\")).Append("\"");
                }
                else if (((JToken)val).Type == JTokenType.Boolean)
                {
                    string value = val.ToString().ToLower();
                    appender.Append("\"").Append(key).Append("\":").Append(value);
                }
                else
                {
                    string value = val.ToString();
                    appender.Append("\"").Append(key).Append("\":").Append(value);
                }
                isFirstEle = false;
            }
            appender.Append("}");
            return appender.ToString();
        }


        public static String GetTime()
        {
            return DateTime.Now.ToString("yyyyMMddHHmmss");
        }

        // 发送Post请求
        public static String DoPostForm(String httpUrl, Hashtable param)
        {
            Encoding encoding = Encoding.GetEncoding("utf-8");
            HttpWebResponse response = PostHttps(httpUrl, param, encoding);
            Stream stream = response.GetResponseStream();
            StreamReader sr = new StreamReader(stream);
            return sr.ReadToEnd();
        }

        private static bool CheckValidationResult(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            return true; //信任所有https站点证书，不安全，请勿在生产环境中使用。
        }

        private static HttpWebResponse PostHttps(string url, Hashtable param, Encoding encoding)
        {
            HttpWebRequest request = null;
            //ServicePointManager.ServerCertificateValidationCallback = new System.Net.Security.RemoteCertificateValidationCallback(CheckValidationResult); // 请勿在生产环境中使用该行程序
            request = WebRequest.Create(url) as HttpWebRequest;
            request.ProtocolVersion = HttpVersion.Version11;
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.Timeout = 15000;
            request.KeepAlive = false;
            request.ReadWriteTimeout = 60000;

            byte[] data = encoding.GetBytes(CreateLinkString(param));
            request.ContentLength = data.Length;
            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(data, 0, data.Length);
            }

            WebResponse res;
            try { res = request.GetResponse(); }
            catch (WebException e)
            {
                res = e.Response;
            }
            return (HttpWebResponse)res;
        }

        private static string CreateLinkString(Hashtable param)
        {
            IEnumerator keys = param.Keys.GetEnumerator();
            StringBuilder prestr = new StringBuilder();
            int i = 0;
            while (keys.MoveNext())
            {
                i++;
                string key = keys.Current as string;
                string value = param[key] as string;
                if (i == param.Count)
                {
                    prestr.Append(key).Append("=").Append(value);
                }
                else
                {
                    prestr.Append(key).Append("=").Append(value).Append("&");
                }
            }
            return prestr.ToString();
        }
    }
}
