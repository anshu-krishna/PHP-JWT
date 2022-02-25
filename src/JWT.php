<?php
namespace Krishna\JWT;

use stdClass;

class JWT {
	const Reserved = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat'];
	private
		$error = 'JWT: Token not loaded',
		$head,
		$body,
		$sig;
	
	public function __construct() {
		$this->head = (object) ['code' => null, 'value' => null];
		$this->body = (object) ['code' => null, 'value' => null];
		$this->sig = (object) ['code' => null, 'value' => null];
	}
	
	public function load(string $token) {
		$token = explode('.', $token);
		if(count($token) != 3) {
			$this->error = "JWT: Invalid token loaded";
			return;
		}
		
		[$head, $body, $sig] = $token;
		
		$head_val = BASE64JSON::decode($head);
		if(!is_array($head_val)) {
			$this->error = "JWT: Invalid token loaded";
			return;
		}

		$body_val = BASE64JSON::decode($body);
		if(!is_array($body_val)) {
			$this->error = "JWT: Invalid token loaded";
			return;
		}

		$sig_val = BASE64URL::decode($sig);
		if($sig_val === null) {
			$this->error = "JWT: Invalid token loaded";
			return;
		}

		$this->head->code = $head;
		$this->head->value = (object) $head_val;

		$this->body->code = $body;
		$this->body->value = (object) $body_val;

		$this->sig->code = $sig;
		$this->sig->value = $sig_val;

		$this->error = null;
	}

	private function verify_sig(string $key) : bool{
		if($this->error !== null) {
			return false;
		}
		if(
			!property_exists($this->head->value, 'typ')
			|| $this->head->value->typ !== 'JWT'
		) {
			$this->error = "JWT: Token is not JWT";
			return false;
		}

		if(
			!property_exists($this->head->value, 'alg')
			|| !is_string($this->head->value->alg)
		) {
			$this->error = "JWT: Token algrithm not found";
			return false;
		}
		$alg = __NAMESPACE__ . "\\Algos\\{$this->head->value->alg}";
		if(!class_exists($alg)) {
			$this->error = "JWT: Token algorithm is not supported";
			return false;
		}

		$sig = $this->sig->value;
		if(!is_string($sig)) {
			$this->error = "JWT: Token signature is invalid";
			return false;
		}

		return $alg::verify($this->head->code, $this->body->code, $sig, $key);
	}

	private function verify_std_claims(
		int $exp = DefaultConfig::Exp,
		int $leeway = DefaultConfig::Leeway,
		?array $mandatory = DefaultConfig::Mandatory, 
		?string $iss = DefaultConfig::Iss,
		?array $auth_iss = DefaultConfig::Auth_iss,
		?array $aud_for = DefaultConfig::Aud_for,
	) : bool {
		// Test is all the mandatory claims are present
		if($mandatory !== null) {
			foreach($mandatory as $m) {
				if(is_string($m) && !property_exists($this->body->value, $m)) {
					$this->error = "JWT: '{$m}' is mandatory";
					return false;
				}
			}
		}
		// Test if token is from an authorised issuer
		if($auth_iss !== null) {
			if(property_exists($this->body->value, 'iss')) {
				$iss = $this->body->value->iss;
				if(!in_array($iss, $auth_iss, true)) {
					$this->error = 'JWT: Token is not from authorised issuer';
					return false;
				}
			}
		}
		// Test if recipient is an audience for the token
		if(property_exists($this->body->value, 'aud')) {
			$aud = $this->body->value->aud;
			if(is_string($aud)) {
				$aud = [$aud];
			}
			if(is_array($aud)) {
				if($aud_for === null) {
					$this->error = 'JWT: Token is not for this audience';
					return false;
				}
				if(is_string($aud_for)) {
					$aud_for = [$aud_for];
				}
				$intersect = array_intersect($aud, $aud_for);
				if(!count($intersect) > 0) {
					$this->error = 'JWT: Token is not for this audience';
					return false;
				}
			}
		}
		// Normalise leeway
		if($leeway < 0) {
			$leeway = 0;
		}
		$now = time();
		// Check if Token has expired
		if(property_exists($this->body->value, ' exp')) {
			$exp = $this->body->value->exp;
			if(
				is_integer($exp)
				&& ($exp <= ($now - $leeway))
			) {
				$this->error = 'JWT: Token has expired';
				return false;
			}
		}
		// Check if token is from future
		if(property_exists($this->body->value, 'iat')) {
			$iat = $this->body->value->iat;
			if(
				is_integer($iat)
				&& ($iat > ($now + $leeway))
			) {
				$this->error = 'JWT: Token is from future';
				return false;
			}
		}
		// Check if token is activated
		if(property_exists($this->body->value, 'nbf')) {
			$nbf = $this->body->value->nbf;
			if(
				is_integer($nbf)
				&& (($nbf - $now) > $leeway)
			) {
				$this->error = 'JWT: Token is not yet active';
				return false;
			}
		}

		return true;
	}

	public function verify(
		string $key,
		?callable $user_claims_verifier = null,
		int $exp = DefaultConfig::Exp,
		int $leeway = DefaultConfig::Leeway,
		?array $mandatory = DefaultConfig::Mandatory, 
		?string $iss = DefaultConfig::Iss,
		?array $auth_iss = DefaultConfig::Auth_iss,
		?array $aud_for = DefaultConfig::Aud_for,
	) : bool {
		if($this->verify_sig($key) && $this->verify_std_claims(
			...[
				'exp' => $exp,
				'leeway' => $leeway,
				'mandatory' => $mandatory,
				'iss' => $iss,
				'auth_iss' => $auth_iss,
				'aud_for' => $aud_for
			]
		)) {
			if($user_claims_verifier !== null) {
				$r = $user_claims_verifier($this->body->value);
				if(is_bool($r)) {
					return $r;
				}
				$this->error = 'JWT: User-claims test verifier is faulty.';
				return false;
			}
			return true;
		}
		return false;
	}

	public function sign(string $alg, string $key) : ?string {
		$head = $this->head->value;
		if($head === null) {
			$this->error = "JWT: Invalid token header";
			return false;
		}

		$head->alg = $alg;
		$head->typ = 'JWT';

		$alg = __NAMESPACE__ . "\\Algos\\{$alg}";
		if(!class_exists($alg)) {
			$this->error = "JWT: Token algorithm is not supported";
			return null;
		}

		$head_code = Base64JSON::encode($head);
		if($head_code === null) {
			$this->error = "JWT: Unable to encode token header";
			return null;
		}

		$body = $this->body->value;
		if($body === null) {
			$this->error = "JWT: Token body is empty";
			return null;
		}
		$body_code = Base64JSON::encode($body);
		if($body_code === null) {
			$this->error = "JWT: Unable to encode token body";
			return null;
		}
		
		$sig = $alg::sign($head_code, $body_code, $key);
		if($sig === null) {
			$this->error = "JWT: Unable to sign";
			return null;
		}
		$sig_code = Base64URL::encode($sig);

		if($sig_code === null) {
			$this->error = "JWT: Unable to encode token signature";
			return null;
		}

		$this->head->value = $head;
		$this->head->code = $head_code;

		$this->body->value = $body;
		$this->body->code = $body_code;

		$this->sig->value = $sig;
		$this->sig->code = $sig_code;

		return "{$this->head->code}.{$this->body->code}.{$this->sig->code}";
	}
}