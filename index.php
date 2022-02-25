<?php
require_once "vendor/autoload.php";

use Krishna\JWT\JWT;

function vd(mixed $value) {
	echo '<pre style="white-space:pre-wrap">';
	// var_dump($value);
	print_r($value);
	echo '</pre><hr />';
}

$jwt = new JWT;

$jwt->load('eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjIsIm5iZiI6MTYxNTQxMjMwN30.PJRaWk4xR38vp-6NBxJrLwyRA2im2nI36GaFxzpLtGyK_E9KwBvfBTVR1axScL0GeWe1GjWDCKtqQMnm8fmmxQ');

// vd($jwt);

vd($jwt->verify('your-256-bit-secret'));
vd($jwt);

// vd($jwt->sign('HS512', 'your-256-bit-secret'));
// vd($jwt);

// vd($jwt->sign('RS256', '-----BEGIN RSA PRIVATE KEY-----
// MIIEpAIBAAKCAQEAthNDmgvSfWTwwqPFY4fqTHbKXqFHPT3HKU0rbaUoeG9nM+9i
// hsqzAy0MtaymyvLY3EKv3GOZsCK9VJNjf8WEBlhw/YKeaUkXp9XZx7Nce/9ApgDy
// kxHZtbirQSuhr4w64aVI3cIrGj3ulj6iwSmh4FCiH2/LrWDXSB9xd7Ox//qzRT4/
// FvkmGwlY8FSrKrpRq16jJl+0+ClzAcyIVsNIxtgITpw3zUdxqGtCtVbCv7PTris2
// Hyv4uMFa3yI9CwpPge8YYcaE3ipX8TLE7V9YzA2cIyXAUdKuJXq7a5uu3NapA1DM
// nqhvQtJzeBsNGp7M8LsUUFj/1IaXoQnETGefUwIDAQABAoIBAQCmnJw44+aaznqu
// cfTXrnENxYpL6+NnvBd6yN4buI1/H9pdoQoU9Hm5R0khGjuK7Yzaib+pug7SKgf8
// 096x9klpERdcNGHHUJZwA/YEkzHnWd2LysQvJp+FddZojYeoP3dGMtyp6NtOaSvh
// mrGOdw1lWgPxJnlIT5zQp81KT0psRSsMGcw63jPfdjccBPnlD327VvpjOtpfxxoZ
// fWQ81FtfeQiCMLtlMeUurfE6gGUodNUTWShDGdBelEtdL9gdtkxekI7Ah8drB+sK
// xluHs/QgkvUbfwRF/yGfIq7PHNcNmx80wQk+DAaVCZWnU+ihCA/OTzldaF+44ET1
// oMg/ldM5AoGBAPkGRgPtBF5mRiUvtwfbpiZ1B25MLuVtEphZ9mHlZCf9QDvwaqug
// 2ejg5alQslvihgmao6Wn3cGiJ9illV/PaTXgruWhI1Tpm++42Zm+UpHaD3uZzITo
// VbjLnRqDDfMhOjgZM5ql4HORWPGicDJoXVeXqAhffNEw7C6zGKNRyavfAoGBALss
// 57FQsoNxJ2vEA2i5ha3ydeZYX5BD5uMNz2PA8URl36qutH0D/kOTmLTX67zuRVm4
// +MKIag3ISXYynwfWNO82TE2SkkH8ur3oWtlpZ9jQ8rWojFWC0kDm80IpGkSLMt0G
// XzuDFj5OeCJK1C4XKUfvhGIAAbQp8/OS8B4fIrsNAoGAKW+yzMpulKqd92gWI5eX
// 8QQ+JUtF7mUU2Ab4KVf7L3BDdPXPOhm8yLRLYr4Lv6BUv1pc6p6hFqw9xx3eWh/w
// GMf3Mjx63ZE1olD23E8//Ab11pJD5sWmJeazkIrIEnGv90+yN4Rsca54x1RJKQoW
// phGVIzeIVGK4mhiw+9QLI68CgYEAkEz9TqE1DsrEpntWWX11xvX+2RfWjOUccn2q
// HnCYUK/tcKwBr8PNWZHHj9xK/LwBMTu+ZFNA1+FKaVp7alJFOwp0ZvWR1leeLFye
// 9bAihHAKPex0TFRv/eNPNPl1K9TY4LdR4hKcqmpaia2AyQvIIpJQUDFLHvedAHKO
// tdoxL10CgYB1dmQzm05FFh/RBpb6EnI6Z3rjAFVd0WiEWC8F9ed+qKedAMdZtY94
// MHeuNAW0i3D1mehgAakDwwjebMuYZ8bTidgXKW6pWQRT6EymHAfWEFzxYSW2NZ7r
// lX5szGrNqEe0u2R7mct5CFeSj3UNXbDsSX42cu4+2SF+nUl9CuETmw==
// -----END RSA PRIVATE KEY-----'));
// vd($jwt);