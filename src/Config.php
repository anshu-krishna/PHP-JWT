<?php
namespace Krishna\JWT;

class Config {
	public function __construct(
		public array $required = ['iss', 'iat', 'exp', 'nbf', 'jti'],
		public string $issuer = 'test.server',
		public ?array $authorised_issuer = null,
		public int $exp_delay = 600, // in seconds
		public int $leeway = 2, // in seconds
		public ?array $audience_for = null
	) {
		if($this->leeway < 0) {
			$this->leeway = 0;
		}
	}
}