<style type="text/css">
	div.cntr {
		display: grid;
		grid-template-columns: auto 1fr auto auto;
		/* grid-template-columns: auto 1fr; */
		border: 1px solid;
		align-items: center;
		margin: 5px;
	}
	pre.cntr {
		display: block;
		border: 1px solid #99f;
		white-space: pre-wrap;
		box-sizing: border-box;
		padding: 5px;
		height: 100%;
		max-width: 100%;
		white-space: pre-wrap;
		word-break: break-all;
	}
	div.cntr > span {
		border: 1px solid #99f;
		font-weight: bold;
		height: 100%;
		padding: 10px;
		box-sizing: border-box;
	}
</style>
<?php
function objToString($object) {
	if($object === NULL) {
		return 'NULL';
	} elseif ($object === FALSE) {
		return 'FALSE';
	} elseif ($object === TRUE) {
		return 'TRUE';
	} else {
		return print_r($object, TRUE);
	}
}
function echoTestResult($msg, $obj, $error, $second_col_name = "Error") {
	echo "<div class=\"cntr\"><span>{$msg}</span><pre class=\"cntr\">";
	// var_dump($obj);
	echo objToString($obj);
	echo "</pre><span>{$second_col_name}</span><pre class=\"cntr\">";
	// var_dump($error);
	echo objToString($error);
	echo "</pre></div>";
}

require_once "../jwt.php";

function header_encoded(string $algo) {
	$header = [
		"alg" => $algo,
		"typ" => "JWT"
	];
	return JWT::encode64(json_encode($header));
}

$key_HS256 = JWT::$CONFIG["keys"]["HS256"][0];
$key_HS512 = JWT::$CONFIG["keys"]["HS512"];

$key_RS256 = JWT::$CONFIG["keys"]["RS256"][0];
$key_RS512 = JWT::$CONFIG["keys"]["RS512"];

$now  = time();
$payload = [
	"iss" => "token.friend.com",
	"aud" => "app.token.com",
	"iat" => $now,
	"nbf" => $now,
	"exp" => $now + 600,
	"name" => "Anshu Krishna"
];

$settings = [
	"mandatory_claims" => ["iss", "iat", "nbf"], // these claims must always be present
	"iss" => "token.test.com", // used when issuing token
	"authorized_iss" => ["token.test.com", "token.friend.com"], // list of valid issuer
	"aud" => "app.token.com", // exp is in seconds
	"exp" => 600, //leeway is in seconds
	"leeway" => 30
];
$error = NULL;
echoTestResult("Payload", json_encode($payload, JSON_PRETTY_PRINT), $error);

$payload_encoded = JWT::encode64(json_encode($payload));
/*****************************************************************************************/
$error = NULL;
$std_claims_verified = JWT::verify_std_claims($payload, $settings, $error);
echoTestResult("Verify Std Claims", $std_claims_verified, $error);
/*****************************************************************************************/
$error = NULL;
$sign_HS256 = JWT::calc_sig("HS256", $key_HS256, header_encoded('HS256'), $payload_encoded, $error);
echoTestResult("Signature HS256", $sign_HS256, $error);
$error = NULL;
$verify_HS256 = JWT::verify_sig("HS256", $key_HS256, header_encoded('HS256'), $payload_encoded, $sign_HS256, $error);
echoTestResult("Verify Signature HS256", $verify_HS256, $error);
/*****************************************************************************************/
$error = NULL;
$sign_HS512 = JWT::calc_sig("HS512", $key_HS512, header_encoded('HS512'), $payload_encoded, $error);
echoTestResult("Signature HS512", $sign_HS512, $error);
$error = NULL;
$verify_HS512 = JWT::verify_sig("HS512", $key_HS512, header_encoded('HS512'), $payload_encoded, $sign_HS512, $error);
echoTestResult("Verify Signature HS512", $verify_HS512, $error);
/*****************************************************************************************/
$error = NULL;
$sign_RS256 = JWT::calc_sig("RS256", $key_RS256->private, header_encoded('RS256'), $payload_encoded, $error);
echoTestResult("Signature RS256", $sign_RS256, $error);
$error = NULL;
$verify_RS256 = JWT::verify_sig("RS256", $key_RS256->public, header_encoded('RS256'), $payload_encoded, $sign_RS256, $error);
echoTestResult("Verify Signature RS256", $verify_RS256, $error);
/*****************************************************************************************/
$error = NULL;
$sign_RS512 = JWT::calc_sig("RS512", $key_RS512->private, header_encoded('RS512'), $payload_encoded, $error);
echoTestResult("Signature RS512", $sign_RS512, $error);
$error = NULL;
$verify_RS512 = JWT::verify_sig("RS512", $key_RS512->public, header_encoded('RS512'), $payload_encoded, $sign_RS512, $error);
echoTestResult("Verify Signature RS512", $verify_RS512, $error);
/*****************************************************************************************/
$error = NULL;
$token_HS512 = JWT::generate_token("HS512", $key_HS512, $payload, $error);
echoTestResult("Token HS512",  $token_HS512, $error);
/*****************************************************************************************/
$error = NULL;
$token_RS256 = JWT::generate_token("RS256", $key_RS256->private, $payload, $error);
echoTestResult("Token HS256",  $token_RS256, $error);
/*****************************************************************************************/
$error = NULL;
$key_from_config = JWT::get_key_from_config("HS256");
echoTestResult("Key from config HS256 (random from array)", $key_from_config, $error);
$key_from_config = JWT::get_key_from_config("HS256", 2);
echoTestResult("Key from config HS256 (index 2 in array)", $key_from_config, $error);
$key_from_config = JWT::get_key_from_config("HS512");
echoTestResult("Key from config HS512 (only one value no array)", $key_from_config, $error);
/*****************************************************************************************/
$error = NULL;
$gen_std_claims = JWT::gen_std_claims_from_config();
echoTestResult("Generated Std Claims from config", $gen_std_claims, $error);
/*****************************************************************************************/
$error = NULL;
echoTestResult("JWT config from file", JWT::$CONFIG, $error);
?>