<?php
namespace Krishna\JWT;

use Krishna\DataValidator\Returner;
use Krishna\DataValidator\Types\StringType;

class TokenStringType implements \Krishna\DataValidator\TypeInterface {
	public static function validate($token, bool $allow_null = false) : Returner {
		$token = StringType::validate($token);
		if(!$token->valid) {
			return Returner::invalid('Invalid token: Expected string');
		}
		$token = $token->value;
		$token = explode('.', $token);
		if(count($token) !== 3) {
			return Returner::invalid('Invalid token: Expected string with 3 parts');
		}
		return Returner::valid([
			'encoded' => [
				'head' => $token[0],
				'body' => $token[1],
				'sig' => $token[2]
			],
			'value' => [
				'head' => $token[0],
				'body' => $token[1],
				'sig' => $token[2]
			]
		]);
	}
}