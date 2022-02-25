<?php
namespace Krishna\JWT\Algos;
use Krishna\JWT\Algo;

abstract class RS256 implements Algo {
	static function sign(string $head, string $body, string $key) : ?string {
		$sig = '';
		openssl_sign("{$head}.{$body}", $sig, $key, 'RSA-SHA256');
		if($sig === false) {
			return null;
		}
		return $sig;
	}
	static function verify(string $head, string $body, string $sig, string $key) : bool {
		return openssl_verify("{$head}.{$body}", $sig, $key, 'RSA-SHA256') === 1;
	}
}