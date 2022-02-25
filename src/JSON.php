<?php
namespace Krishna\JWT;
abstract class JSON {
	public static function encode(mixed $value) : ?string {
		$enc = json_encode($value, JSON_PARTIAL_OUTPUT_ON_ERROR);
		if($enc === false) {
			return null;
		}
		return $enc;
	}
	public static function decode(string $str) {
		return json_decode($str, TRUE);
	}
}