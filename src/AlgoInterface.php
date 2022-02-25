<?php
namespace Krishna\JWT;

interface AlgoInterface {
	static function sign(string $plain, string $key) : ?string;
	static function verify(string $cypher, string $sig, string $key) : bool;
}