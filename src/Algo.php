<?php
namespace Krishna\JWT;

interface Algo {
	static function sign(string $head, string $body, string $key) : ?string;
	static function verify(string $head, string $body, string $sig, string $key) : bool;
}