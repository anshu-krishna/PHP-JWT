<?php
return [
	"mandatory_claims" => ["iss", "iat", "nbf"], // these claims must always be present
	"iss" => "token.test.com", // used when issuing token
	"authorized_iss" => ["token.test.com", "token.friend.com"], // list of valid issuer
	"aud" => "app.token.com", // exp is in seconds
	"exp" => 600, //leeway is in seconds
	"leeway" => 30,

	"keys" => [
		"HS256" => [
			'aNdRgUkXp2r5u8x/A?D(G+KbPeShVmYq',
			'C*F-JaNdRgUkXp2s5v8y/B?D(G+KbPeS',
			'!z$C&F)J@NcRfUjXn2r5u8x/A?D*G-Ka'
		],
		"HS512" => 'UkXp2s5v8x/A?D(G+KbPeShVmYq3t6w9z$B&E)H@McQfTjWnZr4u7x!A%D*F-JaN',
		"RS256" => [(object) ["private" => '-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAthNDmgvSfWTwwqPFY4fqTHbKXqFHPT3HKU0rbaUoeG9nM+9i
hsqzAy0MtaymyvLY3EKv3GOZsCK9VJNjf8WEBlhw/YKeaUkXp9XZx7Nce/9ApgDy
kxHZtbirQSuhr4w64aVI3cIrGj3ulj6iwSmh4FCiH2/LrWDXSB9xd7Ox//qzRT4/
FvkmGwlY8FSrKrpRq16jJl+0+ClzAcyIVsNIxtgITpw3zUdxqGtCtVbCv7PTris2
Hyv4uMFa3yI9CwpPge8YYcaE3ipX8TLE7V9YzA2cIyXAUdKuJXq7a5uu3NapA1DM
nqhvQtJzeBsNGp7M8LsUUFj/1IaXoQnETGefUwIDAQABAoIBAQCmnJw44+aaznqu
cfTXrnENxYpL6+NnvBd6yN4buI1/H9pdoQoU9Hm5R0khGjuK7Yzaib+pug7SKgf8
096x9klpERdcNGHHUJZwA/YEkzHnWd2LysQvJp+FddZojYeoP3dGMtyp6NtOaSvh
mrGOdw1lWgPxJnlIT5zQp81KT0psRSsMGcw63jPfdjccBPnlD327VvpjOtpfxxoZ
fWQ81FtfeQiCMLtlMeUurfE6gGUodNUTWShDGdBelEtdL9gdtkxekI7Ah8drB+sK
xluHs/QgkvUbfwRF/yGfIq7PHNcNmx80wQk+DAaVCZWnU+ihCA/OTzldaF+44ET1
oMg/ldM5AoGBAPkGRgPtBF5mRiUvtwfbpiZ1B25MLuVtEphZ9mHlZCf9QDvwaqug
2ejg5alQslvihgmao6Wn3cGiJ9illV/PaTXgruWhI1Tpm++42Zm+UpHaD3uZzITo
VbjLnRqDDfMhOjgZM5ql4HORWPGicDJoXVeXqAhffNEw7C6zGKNRyavfAoGBALss
57FQsoNxJ2vEA2i5ha3ydeZYX5BD5uMNz2PA8URl36qutH0D/kOTmLTX67zuRVm4
+MKIag3ISXYynwfWNO82TE2SkkH8ur3oWtlpZ9jQ8rWojFWC0kDm80IpGkSLMt0G
XzuDFj5OeCJK1C4XKUfvhGIAAbQp8/OS8B4fIrsNAoGAKW+yzMpulKqd92gWI5eX
8QQ+JUtF7mUU2Ab4KVf7L3BDdPXPOhm8yLRLYr4Lv6BUv1pc6p6hFqw9xx3eWh/w
GMf3Mjx63ZE1olD23E8//Ab11pJD5sWmJeazkIrIEnGv90+yN4Rsca54x1RJKQoW
phGVIzeIVGK4mhiw+9QLI68CgYEAkEz9TqE1DsrEpntWWX11xvX+2RfWjOUccn2q
HnCYUK/tcKwBr8PNWZHHj9xK/LwBMTu+ZFNA1+FKaVp7alJFOwp0ZvWR1leeLFye
9bAihHAKPex0TFRv/eNPNPl1K9TY4LdR4hKcqmpaia2AyQvIIpJQUDFLHvedAHKO
tdoxL10CgYB1dmQzm05FFh/RBpb6EnI6Z3rjAFVd0WiEWC8F9ed+qKedAMdZtY94
MHeuNAW0i3D1mehgAakDwwjebMuYZ8bTidgXKW6pWQRT6EymHAfWEFzxYSW2NZ7r
lX5szGrNqEe0u2R7mct5CFeSj3UNXbDsSX42cu4+2SF+nUl9CuETmw==
-----END RSA PRIVATE KEY-----', "public" => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAthNDmgvSfWTwwqPFY4fq
THbKXqFHPT3HKU0rbaUoeG9nM+9ihsqzAy0MtaymyvLY3EKv3GOZsCK9VJNjf8WE
Blhw/YKeaUkXp9XZx7Nce/9ApgDykxHZtbirQSuhr4w64aVI3cIrGj3ulj6iwSmh
4FCiH2/LrWDXSB9xd7Ox//qzRT4/FvkmGwlY8FSrKrpRq16jJl+0+ClzAcyIVsNI
xtgITpw3zUdxqGtCtVbCv7PTris2Hyv4uMFa3yI9CwpPge8YYcaE3ipX8TLE7V9Y
zA2cIyXAUdKuJXq7a5uu3NapA1DMnqhvQtJzeBsNGp7M8LsUUFj/1IaXoQnETGef
UwIDAQAB
-----END PUBLIC KEY-----'], (object) ["private" => '-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEApTn3JeKv/hlJWPiUPJMn8AY/KZp+aRXfd1TZJKWXhIfioIW/
Xs9R88rGFp3NO3HBLUUPUNzbPM7aSIZx3XGjs3If/wb3C+KFfXVDCeM/h3Yu39v8
zoNTXRcezM+ZmHujLGThuzoeONZzTJEZ0o8tzFB9Ln0ub74n3SgqTiSnE9PwqW8B
O5lqAqTAocxLfbaxgrVsBT93fmB9/vlFei1aYfA7JYnuSvSGp4mKSpL4q/rifgWs
Ac3FnrkGz2hB8tbQJOpX48Usjgnfx10WFQ8Sz1E2Q8zOWGdsOI9t0jYL7Wqep0Oo
6PiFUtZcGLHiwJ+7H/tqelDni2Jtc/EPLER8DQIDAQABAoIBAQCEBK3aoqd2w6Oc
qHphcD9wBL3BM0WgF68HfU9Hfdx0M9M76cJAMi1MO5BNj+blgX4V+uFC/kVa7/jw
DCS9CMkBX8X7EwiggW2iEejv5JjlVuQbUH5OUBZzAj9E7PfQI7H8jdrjq4tsZMWZ
vzK/0FGKuCFd3P4WoPzfM/GhoJ2zM9IkcQn3BA/pR9+/QaNCYC5yLmoQ8esyQxMm
JL1mQe5tUEz+xr4RMvlAXYJTL3ytI6Kycda8v3sMDoUbi0VX6jcu1pwxcP1MzbyQ
FoTykjEiXxwy8m2JxRi7T6fUokADsMuASiPCFgxXKhvI4Vov0iNj7a5xT6J8aE/y
sLWIdDLNAoGBAOJKarBvhldE0mL2w8G0NcGe/VLTfB8yx+6lDooNITYNoyS1MXTa
xpi5KCG5dHpTHt8s2KOgZBJ9pJfQSGc0jHvLEC6CpLHZ9EHyME+Nl7YU/hMqPZcc
5xOBuUFCskHonZFnfQZH96j+Vv8UPpv/EWLo+/5JTVtbE9ofIOgwz8X3AoGBALrr
MQG2HnMga1mKlbLeCMguZUlWT7/bodd6nQ6MshZraWCdm2b7wNvj1ixUPEMLGiZg
/4q7SWzUwjLsVIbK58+JqRBLf4Nhy++r44+tQ/aVjOAfn5I4mWYkQocjXr+rZrCf
EITV8Jf6sFMVXqA9NzYOhflkwtJHVsCvMDwil30bAoGBAMKdM5JX59an9rRr+0Fd
JhpGDSGthoMiXjZMt+tcjWJ6agOI3WbdPI1eODiA0b7eO5++ZvaaW1ZXvjVeSNaR
p/xTULBfZRscEmigzJGueXp8JWMAIgYTMlxhZZzNqpbqYpEJysmbHVC2pMUteQca
X66MJySzkBbwhmtB+EAYsqhTAoGBAIhikbiI9QDV195W01HW1puR1s/DDZ+VFyrN
yYlTOaJIL3SSq1BiQ19uh9iCghH9KNB2GB9W9oVVXHmhnS9ZH/l7nYNJQzpPAmnX
hsxQBXYHuunRyTH84Fj5/hzyvvCllOEsvvXd0JZkEYId5pSO9hkYUcMeNVUPPoqL
iWtnZhefAoGAUIzacPFtuVuxHQcATfi03vTNAGv7qhKIMOwTvn2jdIDR7LymojFM
WPQHf3gPiHLWYCRhcEKJiB7iBjX7jDhK8ffMxcCMS2tmZSej7VPegOmSFy4x48zF
LqcQtXFJDk38uasc7ytVJoWNwbNlUrQy/lo23cH4g+LTnEL1yFkxo/I=
-----END RSA PRIVATE KEY-----', "public" => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApTn3JeKv/hlJWPiUPJMn
8AY/KZp+aRXfd1TZJKWXhIfioIW/Xs9R88rGFp3NO3HBLUUPUNzbPM7aSIZx3XGj
s3If/wb3C+KFfXVDCeM/h3Yu39v8zoNTXRcezM+ZmHujLGThuzoeONZzTJEZ0o8t
zFB9Ln0ub74n3SgqTiSnE9PwqW8BO5lqAqTAocxLfbaxgrVsBT93fmB9/vlFei1a
YfA7JYnuSvSGp4mKSpL4q/rifgWsAc3FnrkGz2hB8tbQJOpX48Usjgnfx10WFQ8S
z1E2Q8zOWGdsOI9t0jYL7Wqep0Oo6PiFUtZcGLHiwJ+7H/tqelDni2Jtc/EPLER8
DQIDAQAB
-----END PUBLIC KEY-----']],
		"RS512" => (object) ["private" => '-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAoMya46u4H2bPhPLnbP781eUf1cGavB4PdZNT5GDkvlYPdZxt
niO18xh5RvOqT6lJMfwI0aqqJdJ1U+aB80Pqhd2DynllQYPwrCaRWu8yg4GMFRMM
wOQjCzhHCmdOWFI9tjj6Dnm4yZC0ygIsNkHZ2P99tWNwQTsIINrQ9G6U9PeQrMLl
1lYajihbRnlbUlysaTfC5Jl17ixDpUKI2tM0Lhy1OPw8alANp/xsR+gm7fT20Cpb
7FJTAevaU30ZgZtqmAPn+KvTEKwiPPL3jmxPrREonKwOID2LHvmUYRl525NG9ERu
wko1j6ebkCa5ZHV2zjjphEid+CjONVo89yLlkwIDAQABAoIBAErjP3es79FgFmG6
puFyV9peHVd2FVRrQ5Pki3ufTKkAd660rbCqvQB8c28B6F21X6txz8GmFBwNSitK
/VaIWN8DbW+M3gWHJz1lsOiC4imw2cau2o+zMEb3bM6BklE77BXDr2GyescVJ721
CVYzkPuo8ajaqNsYXQ7AGfTc027KY69UDC65Oo5PxPyp6Jm5bVksWCW3MVY9WFkA
9hV64JD9aKMyzxc742nWIj9zNTiZnJvYaol6fLu0ZK3qJAPQRzRx49VoLu4NpoG5
QMzhEHGI2ta7aF9iRNBpyR5knm/R46hn926H45rJdHE4CBNODtzoa57M0lF1RFXN
6EWH24ECgYEA/onYAD4xuT6wVc0bIXVyxGn3smmZbxPjzxa8jeAF52ttylwapgN5
HZZU8S7TdeumRl9DKGaNkXEuWQP63H9KlUsSLc9DUs1S3hT4U+S7Wd1rXxGnqC8v
28FivgFeyPIgEbhpZCAwue+rYlgJSbmChsv7Ehennp+p0p3Z0AIkv2ECgYEAobj4
Y0xO6QW1FmVunwSaRHAYyJVO+hM1/4Qg+GSGfjr+A3/4ZhcIotLJP279M3wiuqlT
LWaPEzTn12m4ifSTIqjpRTa+eA7n5cULG5WuGO64a8I4jvudvsagvQridQWyL1Oc
pASF3Rj5Dz43j3pzswqEfhJTltYgOUfNeLiJDXMCgYEAwGhqgySAactdeD5m98/U
RWzk9FSmyzR5zB0fww9I5zpp78HX0w5lC1yMMRR4fHb5ZdC072E2Om8X3eoIQ41l
T51DzKUT+w+CSKYJYUFR7ghWFbM+zP9+aduxTHe0sql0XHDOGgXLT4JAR0LNIpG8
fTDMRUzkRB/lO3RfJcG5DYECgYAnlWeunlneLVhyn+cgovbDc5CNYAZRrWwVG5ka
UzicIwJThvocutyRRfiePyNYe7TgbVt/jE/Oyq9IiYbytVtiK2fVWh3qsvNNyRn7
6XoQfjXDomlHjgzBSkrDmqttKzS+4r8/YiAFyvwDIB5nTviMxTFCzmeJTuXaP1nq
h3h8QwKBgBnQUojul1+jnQ/GsCmfpePyxh7HH1JSTDB+jY2AhFaokpMMvtIknb37
rj0i6lsYe4SiDIWdbbHKvDQlIXb6kOHdgD6c6/pvhUExfz7h5JQAoLHeroGh1EEb
JfeXrpW9tM8hUJz3KXKRuioV4dlarnSE/8ciWXkgrKx7VWCw3yJ2
-----END RSA PRIVATE KEY-----', "public" => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoMya46u4H2bPhPLnbP78
1eUf1cGavB4PdZNT5GDkvlYPdZxtniO18xh5RvOqT6lJMfwI0aqqJdJ1U+aB80Pq
hd2DynllQYPwrCaRWu8yg4GMFRMMwOQjCzhHCmdOWFI9tjj6Dnm4yZC0ygIsNkHZ
2P99tWNwQTsIINrQ9G6U9PeQrMLl1lYajihbRnlbUlysaTfC5Jl17ixDpUKI2tM0
Lhy1OPw8alANp/xsR+gm7fT20Cpb7FJTAevaU30ZgZtqmAPn+KvTEKwiPPL3jmxP
rREonKwOID2LHvmUYRl525NG9ERuwko1j6ebkCa5ZHV2zjjphEid+CjONVo89yLl
kwIDAQAB
-----END PUBLIC KEY-----']
	]
];
?>