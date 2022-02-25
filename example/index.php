<style>pre{white-space: pre-wrap; word-break: break-all;}</style>
<?php
require_once '../vendor/autoload.php';

use Krishna\JWT\Algo;
use Krishna\JWT\JWT;

$secret = 'your-256-bit-secret';

$jwt = new JWT('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0b2tlbi50ZXN0LmNvbSIsImF1ZCI6ImFwcC50ZXN0LmNvbSIsImlhdCI6MTY0Mzg5MTc1OCwibmJmIjoxNjQzODkxNzU4LCJleHAiOjE2NzI1MzQ4MDAsIm5hbWUiOiJBbnNodSBLcmlzaG5hIiwiY2l0eSI6IkJhbmdhbG9yZSIsImp0aSI6IjZmZGZhY2JkLWU1N2MtNDI1Yy1hNDBmLWM3NjQ5YjBkNDg0MSJ9.QAxcJHEJhhFmmvaifgY79QnBd2bOl1gHAGFVGg5-540');
var_dump(['old jwt' => $jwt]);

echo "<hr />";
var_dump(['Verify' => $jwt->verify($secret)]);

$jwt->config->exp_delay = 10 * 60;
$jwt['msg'] = "hello";
$jwt['name'] = 'AK';
unset($jwt['city']);

$new_jwt = $jwt->sign($secret, Algo::HS512);
echo "<hr />";
var_dump(['Sign' => $new_jwt]);

if($new_jwt->valid) {
	$new_jwt = new JWT($new_jwt->value);
	echo "<hr />";
	var_dump(['new jwt' => $new_jwt]);
}

$jwt = new JWT;
$jwt['name'] = 'AK';
echo "<hr />";
var_dump($jwt);

$jwt->sign($secret, Algo::HS512);

var_dump($jwt);