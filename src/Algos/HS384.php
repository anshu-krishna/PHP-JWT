<?php
namespace Krishna\JWT\Algos;
use Krishna\JWT\Algo;

abstract class HS384 implements Algo {
	static function sign(string $head, string $body, string $key) : ?string {
		return hash_hmac('sha384', "{$head}.{$body}", $key, TRUE);
	}
	static function verify(string $head, string $body, string $sig, string $key) : bool {
		$sig2 = hash_hmac('sha384', "{$head}.{$body}", $key, true);
		return hash_equals($sig2, $sig);
	}
}