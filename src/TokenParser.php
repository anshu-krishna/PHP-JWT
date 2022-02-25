<?php
namespace Krishna\JWT;

use Krishna\DataValidator\RecursiveValidator;
use Krishna\DataValidator\RngFmt\AllowedValues;

final class TokenParser {
	static ?RecursiveValidator $TokenValidator = null;
	public array $encoded = [
		'head' => null,
		'body' => null,
		'sig' => null
	], $value = [
		'head' => [
			'alg' => 'HS256',
			'typ' => 'JWT',
		],
		'body' => [],
		'sig' => ''
	];
	public function __construct(?string $token = null) {
		// Create empty JWT
		if($token === null) return;

		// Init static
		if(self::$TokenValidator === null) {
			self::$TokenValidator = (new RecursiveValidator(TokenStringType::class))->then([
				'value' =>[
					'head' => 'json64',
					'body' => 'json64',
					'sig' => 'string64bin'
				]
			])->then([
				'value' => [
					'head' => [
						'alg' => 'string@' . new AllowedValues(...array_map(function ($c) {return $c->value;}, Algo::cases())),
						'typ' => 'string@' . new AllowedValues('JWT')
					],
					'body' => [
						'?iss' => 'string',
						'?sub' => 'string|null',
						'?aud' => 'mixed',
						'?exp' => 'unsigned',
						'?nbf' => 'unsigned',
						'?iat' => 'unsigned',
						'?kid' => 'unsigned',
						'?jti' => 'string'
					]
				]
			]);
		}
		
		// Check token string structure
		if(!($token = self::$TokenValidator->validate($token))->valid) {
			throw new \Exception("JWT Error; {$token->error['msg']->getFormattedErrors('; ')}");
		}
		$token = $token->value;
		$this->encoded = $token['encoded'];
		$this->value = $token['value'];
	}
}