<?php
/* EXAMPLE CLAIM SETTINGS
"mandatory_claims" => ["iss", "iat", "nbf"], // these claims must always be present
"iss" => "token.test.com", // used when issuing token
"authorized_iss" => ["token.test.com", "token.friend.com"], // list of valid issuer
"aud" => "app.token.com", // exp is in seconds
"exp" => 600, //leeway is in seconds
"leeway" => 30
*/
class JWT {
	const ERR_DEV = 0;
	const ERR_AUTH = 1;

	public static $CONFIG;
	
	public static function encode64(string $str) {
		return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
	}
	public static function decode64(string $str) {
		return base64_decode(strtr($str, '-_', '+/'));
	}
	public static function getval(string $type, &$arr, ...$subkeys) {
		$val = $arr;
		foreach($subkeys as $key) {
			if(is_array($val) && array_key_exists($key, $val)) {
				$val = $val[$key];
			} else {
				return NULL;
			}
		}
		if($type !== "") {
			settype($val, $type);
		}
		return $val;
	}
	public static function calc_sig(string $algo, string $key, string $encoded_header, string $encoded_payload, &$error = NULL) {
		$signature = "";
		switch($algo) {
			case "HS256":
			case "HS384":
			case "HS512":
				switch($algo) {
					case "HS256": $algo = "sha256"; break;
					case "HS384": $algo = "sha384"; break;
					case "HS512": $algo = "sha512"; break;
				}
				$signature = hash_hmac($algo, "{$encoded_header}.{$encoded_payload}", $key, TRUE);
				break;
			case "RS256":
			case "RS384":
			case "RS512":
				switch($algo) {
					case "RS256": $algo = 'RSA-SHA256'; break;
					case "RS384": $algo = 'RSA-SHA348'; break;
					case "RS512": $algo = 'RSA-SHA512'; break;
				}
				$t = openssl_sign("{$encoded_header}.{$encoded_payload}", $signature, $key, $algo);
				if($t === FALSE) {
					$error = ["JWT: Unable to sign", JWT::ERR_DEV];
					return NULL;
				}
				break;
			default:
				$error = ["JWT: Algorithm not supported", JWT::ERR_AUTH];
				return NULL;
				break;
		}
		return JWT::encode64($signature);
	}
	public static function verify_sig(string $algo, string $key, string $encoded_header, string $encoded_payload, $signature, &$error = NULL) {
		$signature = JWT::decode64($signature);
		switch($algo) {
			case "HS256":
			case "HS384":
			case "HS512":
				switch($algo) {
					case "HS256": $algo = "sha256"; break;
					case "HS384": $algo = "sha384"; break;
					case "HS512": $algo = "sha512"; break;
				}
				$signature2 = hash_hmac($algo, "{$encoded_header}.{$encoded_payload}", $key, TRUE);
				$t = hash_equals($signature2, $signature);
				if($t === FALSE) {
					return FALSE;
				}
				break;
			case "RS256":
			case "RS384":
			case "RS512":
				switch($algo) {
					case "RS256": $algo = 'RSA-SHA256'; break;
					case "RS384": $algo = 'RSA-SHA348'; break;
					case "RS512": $algo = 'RSA-SHA512'; break;
				}
				$t = openssl_verify("{$encoded_header}.{$encoded_payload}", $signature, $key, $algo);
				if($t === -1) {
					$error = ["JWT: Unable to verify", JWT::ERR_DEV];
					return NULL;
				} elseif ($t === 0) {
					return FALSE;
				}
				break;
			default:
				$error = ["JWT: Algorithm not supported", JWT::ERR_AUTH];
				return NULL;
				break;
		}
		return TRUE;
	}
	public static function verify_std_claims(array &$payload, array &$claim_settings, &$error = NULL) {
		$mandatory = JWT::getval("", $claim_settings, "mandatory_claims");
		if($mandatory !== NULL) {
			if(!is_array($mandatory)) {
				$error = ["JWT: invalid mandatory claims list", JWT::ERR_DEV];
				return FALSE;
			} else {
				foreach($mandatory as &$claim) {
					if(!array_key_exists($claim, $payload)) {
						$error = ["JWT: '{$claim}' is mandatory", JWT::ERR_AUTH];
						return FALSE;
					}
				}
			}
		}		
		
		$auth_iss = JWT::getval("", $claim_settings, "authorized_iss");
		if($auth_iss !== NULL && !is_array($auth_iss)) {
			$error = ["JWT: invalid authorized iss list", JWT::ERR_DEV];
			return FALSE;
		}

		$aud = JWT::getval("string", $claim_settings, "aud");
		$p_aud = JWT::getval("", $payload, "aud");
		if($aud !== NULL && $p_aud !== NULL && $p_aud !== $aud) {
			$error = ["JWT: not for this audience", JWT::ERR_AUTH];
			return FALSE;
		}
		if($auth_iss !== NULL) {
			$iss = JWT::getval("", $payload, "iss");
			if($iss === NULL) {
				$error = ["JWT: issuer claim is missing", JWT::ERR_AUTH];
				return FALSE;
			}
			if(!in_array($iss, $auth_iss, TRUE)) {
				$error = ["JWT: token is from unauthorized issuer", JWT::ERR_AUTH];
				return FALSE;
			}
		}
		
		$leeway = JWT::getval("int", $claim_settings, "leeway");
		$leeway = ($leeway === NULL) ? 0 : $leeway;
		$now = time();

		$p_exp = JWT::getval("int", $payload, "exp");
		if($p_exp !== NULL && $p_exp <= ($now - $leeway)) {
			$error = ["JWT: token has expired", JWT::ERR_AUTH];
			return FALSE;
		}
		$p_iat = JWT::getval("int", $payload, "iat");
		if($p_iat !== NULL && $p_iat > ($now + $leeway)) {
			$error = ["JWT: token is from future", JWT::ERR_AUTH];
			return FALSE;
		}
		$p_nbf = JWT::getval("int", $payload, "nbf");
		if($p_nbf !== NULL && ($p_nbf - $now) > $leeway) {
			$error = ["JWT: token is not yet active", JWT::ERR_AUTH];
			return FALSE;
		}
		return TRUE;
	}
	public static function generate_token(string $algo, string $key, array &$payload, &$error = NULL) {
		$header = [
			"alg" => $algo,
			"typ" => "JWT"
		];
		$encoded_header = JWT::encode64(json_encode($header));
		$encoded_payload = JWT::encode64(json_encode($payload));

		$sign = JWT::calc_sig($algo, $key, $encoded_header, $encoded_payload, $error);
		if($sign === NULL) {
			return NULL;
		}
		return "{$encoded_header}.{$encoded_payload}.{$sign}";
	}
	public static function get_key_from_config(string $algo, int $kid = -1) {
		$key = JWT::getval("", JWT::$CONFIG, "keys", $algo);
		if($key === NULL) {
			return NULL;
		}
		if(is_array($key)) {
			if($kid > -1) {
				$ret = JWT::getval("", $key, $kid);
				return ($ret === NULL) ? NULL : ["key" => $ret, "kid" => $kid];
			} else {
				$kid = array_rand($key);
				return ["key" => $key[$kid], "kid" => $kid];
			}
		} else {
			return ($kid > -1) ? NULL : ["key" => $key, "kid" => -1];
		}
	}
	public static function gen_std_claims_from_config() {
		$claims = [];
		$iss = JWT::getval("string", JWT::$CONFIG, "iss");
		if($iss !== NULL) {
			$claims["iss"] = $iss;
		}
		$aud = JWT::getval("string", JWT::$CONFIG, "aud");
		if($aud !== NULL) {
			$claims["aud"] = $aud;
		}
		
		$now = time();
		$claims["iat"] = $now;
		$claims["nbf"] = $now;

		$exp = JWT::getval("int", JWT::$CONFIG, "exp");
		/* Default exp is in 5 mins */
		$claims["exp"] = $now + (($exp === NULL) ? 300 : $exp);
		return $claims;
	}

	private $encoded_token = NULL,
		$token = NULL;
	public $error = NULL;
	// public function __construct() {}
	private function process_encoded_token() {
		$is_invalid = FALSE;
		do {
			$tk = explode(".", $this->encoded_token);
			if(count($tk) !== 3) {
				$is_invalid = TRUE;
				break;
			}
			$this->encoded_token = ["header" => $tk[0], "payload" => $tk[1], "signature" => $tk[2]];
			$tk[0] = JWT::decode64($tk[0]);
			$tk[1] = JWT::decode64($tk[1]);

			$tk[0] = json_decode($tk[0], TRUE);
			$tk[1] = json_decode($tk[1], TRUE);
			if(!is_array($tk[0]) || !is_array($tk[1])) {
				$is_invalid = TRUE;
				break;
			}
			$algo = JWT::getval("", $tk[0], "alg");
			if($algo === NULL || JWT::getval("", $tk[0], "typ") !== "JWT") {
				$is_invalid = TRUE;
				break;
			}
			$kid = JWT::getval("int", $tk[1], "kid");
			$kid = ($kid === NULL) ? -1 : $kid;

			$key = JWT::get_key_from_config($algo, $kid);
			if($key === NULL) {
				// $this->error = ["JWT: Algorithm not supported", JWT::ERR_AUTH];
				// return;
				$is_invalid = TRUE;
				break;
			}
			$key = is_object($key["key"]) ? ($key["key"])->public : $key["key"];
			$valid_sig = JWT::verify_sig(
				$algo,
				$key,
				$this->encoded_token["header"],
				$this->encoded_token["payload"],
				$this->encoded_token["signature"],
				$this->error
			);
			if($valid_sig === NULL) {
				return;
			} elseif ($valid_sig=== FALSE) {
				$is_invalid = TRUE;
				break;
			}
			$valid_std_claims = JWT::verify_std_claims($tk[1], JWT::$CONFIG, $this->error);
			if($valid_std_claims === FALSE) {
				return;
			}
			$this->token = ["header" => $tk[0], "payload" => $tk[1]];
		} while(FALSE);
		if($is_invalid === TRUE) {
			$this->error = ["JWT: invalid token", JWT::ERR_AUTH];
			return;
		}
	}
	private function get_from_request_header() {
		$this->error = NULL;
		$headers = getallheaders();
		if(array_key_exists("Authorization", $headers)) {
			preg_match("/^Bearer\s+(.+)/i",$headers["Authorization"], $matches);
			if(count($matches) == 2) {
				$this->encoded_token = $matches[1];
			}
		}
		if($this->encoded_token === NULL) {
			$this->error = ["JWT: token not found", JWT::ERR_AUTH];
			return;
		}
		$this->process_encoded_token();
	}
	private function get_from_post_data() {
		$this->error = NULL;
		if(array_key_exists('Authorization', $_POST)) {
			$this->encoded_token = $_POST['Authorization'];
			$this->process_encoded_token();
		} else {
			$this->error = ["JWT: token not found", JWT::ERR_AUTH];
			return;
		}
	}
	public function find_incoming_token() {
		$this->get_from_request_header();
		if($this->encoded_token !== NULL) {
			return;
		}
		$this->get_from_post_data();
	}
	public function init_new_token(string $algo, int $kid = -1) {
		$this->error = NULL;
		$key = JWT::get_key_from_config($algo, $kid);
		if($key === NULL) {
			$this->error = ["JWT: unable to init token, key not found", JWT::ERR_DEV];
			return;
		}
		$this->encoded_token = NULL;
		$this->token = [
			"header" => [
				"alg" => $algo,
				"typ" => "JWT"
			],
			"payload" => JWT::gen_std_claims_from_config()
		];
		if($key["kid"] !== -1) {
			$this->token["payload"]["kid"] = $key["kid"];
		}
	}
	public function get_token_string() {
		$this->error = NULL;
		do {
			if($this->token === NULL) {
				break;
			}
			$algo = JWT::getval("", $this->token, "header", "alg");
			if($algo === NULL) {
				break;
			}
			$kid = JWT::getval("int", $this->token, "payload", "kid");
			$kid = ($kid === NULL) ? -1 : $kid;
			$key = JWT::get_key_from_config($algo, $kid);
			if($key === NULL) {
				break;
			}
			if($key["kid"] > - 1) {
				$this->token["payload"]["kid"] = $key["kid"];
			}
			$key = is_object($key["key"]) ? $key["key"]->private : $key["key"];
			$tk = JWT::generate_token($algo, $key, $this->token["payload"], $this->error);
			if($tk === NULL) {
				break;
			}
			return $tk;
		} while(FALSE);
		if($this->error === NULL) {
			$this->error = ["JWT:: Unable to generate", JWT::ERR_DEV];
		}
		return NULL;
	}
	public function update_std_claims() {
		if($this->token === NULL) {
			return FALSE;
		}
		$algo = JWT::getval("", $this->token, "header", "alg");
		if($algo === NULL) {
			return FALSE;
		}
		$key = JWT::get_key_from_config($algo);
		$claims = JWT::gen_std_claims_from_config();
		if($key["kid"] > -1) {
			$claims["kid"] = $key["kid"];
		}
		unset($claims["aud"]);
		$this->token["payload"] = array_merge($this->token["payload"], $claims);
		return TRUE;
	}
}

JWT::$CONFIG = (include getcwd() . "/jwt_config.php");
?>