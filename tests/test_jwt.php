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
function printResult($msg, $obj) {
	echo "<div class=\"cntr\"><span>{$msg}</span><pre class=\"cntr\">";
	// var_dump($obj);
	echo objToString($obj);
	// echo "</pre><span>{$second_col_name}</span><pre class=\"cntr\">";
	// var_dump($error);
	// echo objToString($error);
	echo "</pre></div>";
}
require_once "../jwt.php";

$jwt = new JWT();

$jwt->find_incoming_token();
// $jwt->init_new_token("HS256");
printResult("JWT", $jwt);

$jwt->update_std_claims();
$token_string = $jwt->get_token_string();
printResult("JWT String", print_r($jwt, TRUE) . "\n\nToken : " .$token_string);
?>