<?php
namespace Krishna\JWT;
abstract class Base64URL {
	public static function encode(string $str) : string {
		return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
	}
	public static function decode(string $str) : ?string {
		$str = strtr($str, '-_', '+/');
		if(preg_match("/^[a-zA-Z0-9\/+]*={0,2}$/", $str)) {
			return base64_decode($str, TRUE);
		}
		return null;
	}
}