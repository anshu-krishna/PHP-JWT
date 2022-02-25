<?php
namespace Krishna\JWT\AlgoHandler;
use Krishna\JWT\AlgoInterface;
use Krishna\Utilities\StaticOnlyTrait;

final class HS256 implements AlgoInterface {
	use StaticOnlyTrait;
	static function sign(string $plain, string $key) : ?string {
		return hash_hmac('sha256', $plain, $key, TRUE);
	}
	static function verify(string $cypher, string $sig, string $key) : bool {
		$sig2 = hash_hmac('sha256', $cypher, $key, true);
		return hash_equals($sig2, $sig);
	}
}