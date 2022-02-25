<?php
namespace Krishna\JWT;

abstract class DefaultConfig {
	const Mandatory = ['iat', 'nbf']; // Must be null or array
	const Iss = 'token.test'; // Must be URI(string) or null
	const Auth_iss = null; // Must be null or array of URI(string)
	const Exp = 600; // exp: seconds(int)
	const Leeway = 2; // leeway: seconds(int)
	const Aud_for = ['token.test', 'app.test']; // must be null or array of URI(string)
}