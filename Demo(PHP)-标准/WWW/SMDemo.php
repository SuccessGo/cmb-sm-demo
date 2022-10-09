<?php

require_once("Java.inc");

class PhpJavaBridge
{
    var $url = "http://cdctest.cmburl.cn:80/cdcserver/api/v2";
    var $uid = "N002463422";
    var $funcode = "DCLISMOD";
    var $privatekey = "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E=";
    var $symmetrickey = "VuAzSWQhsoNqzn0K";
    var $bankpubkey = "BNsIe9U0x8IeSe4h/dxUzVEz9pie0hDSfMRINRXc7s1UIXfkExnYECF4QqJ2SnHxLv3z/99gsfDQrQ6dzN5lZj0=";

    //账户详细信息查询
    function getntqacinf()
    {
        ini_set('date.timezone', 'Asia/Shanghai');
        $param_data = [];
        $this->funcode = "DCLISMOD";
        $param_data['head'] = [
            'funcode' => $this->funcode,
            'userid' => $this->uid,
            'reqid' => date("YmdHisu", time()) . rand(100000, 200000),
        ];
        $param_data['body'] = [
            'buscod' => 'N02030',
        ];
        $signrequest = $this->sign($param_data, $this->uid);
        $result = $this->curlpost($this->uid, $signrequest);
        print_r($result);
    }

    function strToByte($str)
    {
        return array_slice(unpack("C*", "\0" . $str), 1);
    }

    function byteToStr($bytes)
    {
        $str = '';
        foreach ($bytes as $ch) {
            $str .= chr($ch);
        }
        return $str;
    }

    /**
     * 生成签名
     * @return 签名，本函数不覆盖sign成员变量，如要设置签名需要调用SetSign方法赋值
     */
    function sign($param_data = [], $uid = '')
    {
        $data = [
            "request" => [
                'head' => $param_data['head'],
                'body' => $param_data['body'],
            ],
            "signature" => [
                'sigdat' => "__signature_sigdat__",
                'sigtim' => date('YmdHis', time())
            ]
        ];
        $data = array_filter($data);
        //签名步骤一：ASSIIC码排序
        $data = $this->sort_json($data);
        //签名步骤二：用户签名私钥进行签名SM2
        $cryptor = new Java("dc.demo.DCCryptor");
        $id_iv = substr($uid . "0000000000000000", 0, 16);
        $signed = $cryptor->CMBSM2SignWithSM3($this->strToByte($id_iv), base64_decode($this->privatekey), $this->strToByte(json_encode($data, JSON_UNESCAPED_UNICODE)));

        $data['signature']['sigdat'] = base64_encode($signed);
        //  用户对称密钥（SM4）
        $data = $cryptor->CMBSM4EncryptWithCBC($this->symmetrickey, $this->strToByte($id_iv), $this->strToByte(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)));
        return base64_encode($data);
    }

    public function sort_json($a)
    {
        foreach ($a as $k => $val) {
            if (is_array($val)) { //如果键值是数组，则进行函数递归调用
                ksort($val);
                $a[$k] = $this->sort_json($val);
            }
        }
        return $a;
    }

    //发送post请求
    function curlpost($uid, $param_data)
    {
        if ($param_data) {
            $param_data = [
                "UID" => $this->uid,
                "FUNCODE" => $this->funcode,
                'ALG' => "SM",
                'DATA' => urlencode($param_data)
            ];
            $str = '';
            foreach ($param_data as $k => $val) {
                $str .= $k . '=' . $val . '&';
            }
            $param_data = rtrim($str, '&');
        }
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $this->url);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $param_data);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        $data = curl_exec($curl);
        //返回结果
        if ($data) {
            if (strpos($data, 'ErrMsg')) {
                return $data;
            }

            curl_close($curl);
            $cryptor = new Java("dc.demo.DCCryptor");
            $id_iv = substr($uid . "0000000000000000", 0, 16);
            //解密
            $resplain = $cryptor->CMBSM4DecryptWithCBC($this->symmetrickey, $this->strToByte($id_iv), base64_decode($data));

            $tempjson = json_decode($resplain, true);
            $sigdat = $tempjson['signature']['sigdat'];

            $returnjson = json_decode(str_replace($sigdat, '__signature_sigdat__', $resplain));

            //ASSIIC码排序
            $returnjson = $this->sort_json($returnjson);

            $returnjson = json_encode($returnjson, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

            //验签
            $results = $cryptor->CMBSM2VerifyWithSM3($this->strToByte($id_iv), base64_decode($this->bankpubkey), $this->strToByte($returnjson), base64_decode($sigdat));
            if ($results == '1') {
                //验签通过
                $data = json_decode($returnjson, true);
                $return_data = $returnjson;
            } else {
                $error = '返回报文验签不通过' . $results;
                $return_data = '返回报文验签不通过' . $results;
            }
        } else {
            $error = $curl;
            $return_data = '招商银行系统错误';
        }
        return $return_data;
    }

}

$bridge = new PhpJavaBridge();
$bridge->getntqacinf();
?>