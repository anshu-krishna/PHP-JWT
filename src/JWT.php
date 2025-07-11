<?php
namespace Krishna\JWT;
use Krishna\DataValidator\Returner;
use Krishna\Utilities\Base64;
use Traversable;

class JWT implements \ArrayAccess, \IteratorAggregate, \JsonSerializable  {
	private ?string
		$enc = null,
		$sig = null;
	private ?array
		$head,
		$body;
	private $jti_handler = null;
	private $user_claims_handler = null;

	public function __construct(string|null $token = null, public Config $config = new Config) {
		$token = new TokenParser($token);
		if($token->encoded['head'] !== null && $token->encoded['body'] !== null) {
			$this->enc = "{$token->encoded['head']}.{$token->encoded['body']}";
		}
		$this->head = $token->value['head'];
		$this->body = $token->value['body'];
		$this->sig = $token->value['sig'];
	}
	/* String */
	public function __toString() {
		if($this->enc === null || $this->sig === null) {
			throw new \Exception('JWT Error; Token has not been signed');
		}
		return $this->enc . "." . Base64::encode($this->sig);
	}
	/* Debug */
	public function __debugInfo() {
		return ['enc' => $this->enc, 'sig' => $this->sig, 'head' => $this->head, 'body' => $this->body];
	}
	/* JsonSerializable */
	public function jsonSerialize(): array {
		return [
			'head' => $this->head,
			'body' => $this->body
		];
	}
	/* IteratorAggregate */
	public function getIterator(): \Traversable {
		return new \ArrayIterator($this->body);
	}
	
	/* ArrayAccess Start */
	public function offsetExists(mixed $offset): bool {
		return array_key_exists($offset, $this->body);
	}
	public function offsetGet(mixed $offset): mixed {
		if(array_key_exists($offset, $this->body)) {
			return $this->body[$offset];
		}
		return null;
	}
	public function offsetSet(mixed $offset, mixed $value): void {
		$this->body[$offset] = $value;
	}
	public function offsetUnset(mixed $offset): void {
		unset($this->body[$offset]);
	}
	/* ArrayAccess End */
	
	public function set_jti_handler(callable $handler) {
		$this->jti_handler = $handler;
	}
	public function set_user_claims_handler(callable $handler) {
		$this->user_claims_handler = $handler;
	}

	public function verify(string|array $keys) : Returner {
		$body = &$this->body;

	/*
	* Verify Signature
	*/
		if($this->enc === null) {
			return Returner::invalid('Encoded JWT missing');
		}
		if(is_string($keys)) { $keys = [$keys]; }
		$kid = $body['kid'] ?? 0;

		$algo = Algo::from($this->head['alg']);
		
		if(array_key_exists($kid, $keys)) {
			if(!($sig_result = $algo->verify($this->enc, $this->sig, $keys[$kid]))->valid) {
				return $sig_result;
			}
		} else {
			return Returner::invalid('Invalid kid');
		}

		$conf = &$this->config;

	/*
	* Verify Std Claims
	*/
		// Test is all the required claims are present
		foreach($conf->required as $k) {
			if(!array_key_exists($k, $body)) {
				return Returner::invalid("'{$k}' is required");
			}
		}
		if(
			($body['jti'] ?? false)
			&& is_callable($this->jti_handler)
			&& boolval(($this->jti_handler)($body['jti'])) === false
		) {
			return Returner::invalid('Token has been deactivalted');
		}
		// Test if token is from an authorised issuer
		if(
			($body['iss'] ?? false)
			&& $conf->authorised_issuer !== null
			&& !in_array($body['iss'], $conf->authorised_issuer)
		) {
			return Returner::invalid('Invalid issuer');
		}
		// Test if server is an audience for the token
		if(
			($body['aud'] ?? false)
			&& $conf->audience_for !== null
		) {
			if(is_string($body['aud']) && !in_array($body['aud'], $conf->audience_for)) {
				return Returner::invalid('Token is not for this server');
			} elseif (is_array($body['aud']) && (count(array_intersect($conf->audience_for, $body['aud'])) === 0)) {
				return Returner::invalid('Token is not for this server');
			} else {
				return Returner::invalid('Token is not for this server');
			}
		}

		$NOW = time();

		// Test if Token has expired
		if(
			($body['exp'] ?? false)
			&& $body['exp'] <= ($NOW - $conf->leeway)
		) {
			return Returner::invalid('Token has expired');
		}
		// Test if token is from future
		if(
			($body['iat'] ?? false)
			&& $body['iat'] > ($NOW + $conf->leeway)
		) {
			return Returner::invalid('Token is from future');
		}
		// Test if token is activated
		if(
			($body['nbf'] ?? false)
			&& ($body['nbf'] - $NOW) > $conf->leeway
		) {
			return Returner::invalid('Token is not yet active');
		}

	/*
	* Verify User Claims
	*/
		if(is_callable($this->user_claims_handler)) {
			$claims_result = ($this->user_claims_handler)($body);
			var_dump($claims_result);
			if(($claims_result instanceof Returner) && !$claims_result->valid) {
				return $claims_result;
			}
			if(boolval($claims_result) === false) {
				return Returner::invalid('Invalid token');
			}
		}
		// No errors found
		return Returner::valid();
	}
	public function sign(
		string $key,
		Algo $algo = Algo::HS256,
		array $auto_update = ['iss', 'iat', 'exp', 'nbf', 'jti']
	) : Returner {
		$config = & $this->config;
		$auto_update = array_unique(['iat', 'nbf', ...$auto_update]);
		$NOW = time();
		$auto_vals = [
			'iss' => $config->issuer,
			'iat' => $NOW,
			'exp' => $NOW + $config->exp_delay,
			'nbf' => $NOW,
			'jti' => \Krishna\Utilities\UUID::gen()
		];
		$body = & $this->body;
		foreach($auto_update as $k) {
			if(array_key_exists($k, $auto_vals)) {
				$body[$k] = $auto_vals[$k];
			}
		}
		$this->head['alg'] = $algo->value;
		$this->enc = Base64::encode_json($this->head) . '.' . Base64::encode_json($body);
		if(($sig = $algo->sign($this->enc, $key)) === null) {
			return Returner::invalid('Unable to sign');
		}
		$this->sig = $sig;
		$sig = Base64::encode($sig);
		return Returner::valid("{$this->enc}.{$sig}");
	}
}