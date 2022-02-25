<?php
namespace Krishna\JWT;
abstract class Base64JSON {
	public static function encode(mixed $val) : ?string {
		$val = JSON::encode($val);
		if($val === null) return $val;
		return Base64URL::encode($val);
	}
	public static function decode(string $val) {
		$val = Base64URL::decode($val);
		if($val === null) return $val;
		return JSON::decode($val);
	}
}