<?php
namespace Krishna\JWT\AlgoHandler;
use Krishna\JWT\AlgoInterface;
use Krishna\Utilities\StaticOnlyTrait;

final class RS256 implements AlgoInterface {
	use StaticOnlyTrait;
	static function sign(string $plain, string $key) : ?string {
		$sig = '';
		openssl_sign($plain, $sig, $key, 'RSA-SHA256');
		if($sig === false) {
			return null;
		}
		return $sig;
	}
	static function verify(string $cypher, string $sig, string $key) : bool {
		return openssl_verify($cypher, $sig, $key, 'RSA-SHA256') === 1;
	}
}