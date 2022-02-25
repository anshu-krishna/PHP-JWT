<style type="text/css">
	body {
		padding: 0;
		margin: 0;
		display: grid;
		grid-template-columns: 1fr 1fr;
		grid-gap: 5px;
	}
	div.cntr {
		display: grid;
		grid-template-columns: auto 1fr;
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
require_once "script_caller.php";
require_once "../jwt.php";

function header_encoded(string $algo) {
	$header = [
		"alg" => $algo,
		"typ" => "JWT"
	];
	return JWT::encode64(json_encode($header));
}
$now  = time();
$payload = [
	"iss" => "token.friend.com",
	"aud" => "app.token.com",
	"iat" => $now,
	"nbf" => $now,
	"exp" => $now + 600,
	"name" => "Anshu Krishna",
	"city" => "Bangalore"
];

$settings = [
	"mandatory_claims" => ["iss", "iat", "nbf"], // these claims must always be present
	"iss" => "token.test.com", // used when issuing token
	"authorized_iss" => ["token.test.com", "token.friend.com"], // list of valid issuer
	"aud" => "app.token.com", // exp is in seconds
	"exp" => 600, //leeway is in seconds
	"leeway" => 30
];

$algo = "HS512";
$key = JWT::$CONFIG["keys"][$algo];
// $key = JWT::$CONFIG["keys"][$algo]->private;

// $algo = "HS256";
// $payload["kid"] = 1;
// $key = JWT::$CONFIG["keys"][$algo][$payload["kid"]];
// $key = JWT::$CONFIG["keys"][$algo][$payload["kid"]]->private;

$token = JWT::generate_token($algo, $key, $payload, $error);

// $payload["iat"] = $payload["iat"] + 500;
// $payload["nbf"] = $payload["exp"] + 100;
$payload["exp"] = $payload["exp"] - 900;

$token_2 = JWT::generate_token($algo, $key, $payload, $error);

echo  call_script("POST", "test_jwt.php");

echo  call_script("POST", "test_jwt.php", NULL, [
	"Authorization" => "Bearer 123.456.789"
]);

echo  call_script("POST", "test_jwt.php", NULL, [
	"Authorization" => 'Bearer ' . implode(".", ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
	'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
	'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'])
]);

echo  call_script("POST", "test_jwt.php", NULL, [
	"Authorization" => 'Bearer ' . implode(".", ['eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9',
	'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0',
	'bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh'])
]);

echo  call_script("POST", "test_jwt.php", NULL, [
	"Authorization" => "Bearer {$token_2}"
]);

/* Sending token in post data */
echo  call_script("POST", "test_jwt.php", [
	"Authorization" => $token
]);

echo  call_script("POST", "test_jwt.php", NULL, [
	"Authorization" => "Bearer {$token}"
]);
?>