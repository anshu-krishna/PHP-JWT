<?php
namespace Krishna\JWT\Algos;
use Krishna\JWT\Algo;

abstract class None implements Algo {
	static function sign(string $head, string $body, string $key = '') : ?string {
		return '';
	}
	static function verify(string $head, string $body, string $sig, string $key = '') : bool {
		return $sig === '';
	}
}