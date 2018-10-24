<?php

namespace stylecc\Token;

class WebToken {

    private $key = 'A2DE3-0OYDE-CFGHA-WQVBE';

    public function __construct($key = ''){
        $this->key = $key;
    }

    public function encode($data, $exp = 0) {
        if ($exp == 0) {
            $exp = 7 * 24 * 60 * 60;
        }
        $exp += time();

        $head    = base64_encode(json_encode(['type' => 'JWT', "alg" => "HS256"]));
        $payload = base64_encode(json_encode(['data'=> $data, 'exp'=> $exp]));

        $signature = ("{$head}.{$payload}");
        $signature = hash_hmac('sha256', $signature, $this->key);

        return "{$head}.{$payload}.{$signature}";
    }

    public function decode($token) {
        $array = explode('.', $token);
        if (count($array) != 3) {
            return ['code'=> 10000, 'message'=> '非法令牌', 'data'=> []];
        }

        $signature = ("{$array[0]}.{$array[1]}");
        $signature = hash_hmac('sha256', $signature, $this->key);
        if ($signature != $array[2]) {
            return ['code'=> 10001, 'message'=> '签名错误', 'data'=> []];
        }

        $data = json_decode(base64_decode($array[1]), true);
        return ['code'=> 0, 'message'=> '解密成功', 'data'=> $data['data'], 'exp'=> $data['exp']];
    }
}
