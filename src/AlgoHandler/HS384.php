<?php
namespace Krishna\JWT\AlgoHandler;
use Krishna\JWT\AlgoInterface;
use Krishna\Utilities\StaticOnlyTrait;

final class HS384 implements AlgoInterface {
	use StaticOnlyTrait;
	static function sign(string $plain, string $key) : ?string {
		return hash_hmac('sha384', $plain, $key, TRUE);
	}
	static function verify(string $cypher, string $sig, string $key) : bool {
		$sig2 = hash_hmac('sha384', $cypher, $key, true);
		return hash_equals($sig2, $sig);
	}
}