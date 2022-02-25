# JSON Web Token library for PHP
## Installation:
```
composer require anshu-krishna/php-jwt
```
- Generate JWT
- Verify JWT
- Supported Std Claims:
	- `iss`
	- `sub`
	- `aud`
	- `exp`
	- `nbf`
	- `iat`
	- `jti`
	- `kid`
- Supported Signature Algorithms:
	- `HS256`
	- `HS384`
	- `HS512`
	- `RS256`
	- `RS384`
	- `RS512`

## Example (Basic):
Read and verify JWT:
```php
use Krishna\JWT\JWT;

$secret_key = 'your-secret';

$jwt = new JWT('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0b2tlbi50ZXN0LmNvbSIsImF1ZCI6ImFwcC50ZXN0LmNvbSIsImlhdCI6MTY0Mzg5MTc1OCwibmJmIjoxNjQzODkxNzU4LCJleHAiOjE2NzI1MzQ4MDAsIm5hbWUiOiJBbnNodSBLcmlzaG5hIiwiY2l0eSI6IkJhbmdhbG9yZSIsImp0aSI6IjZmZGZhY2JkLWU1N2MtNDI1Yy1hNDBmLWM3NjQ5YjBkNDg0MSJ9.U7o6m77GP3oX_A_DgjgkS6U9rSLspPkOL_1dQLkr6QM');

var_dump(['JWT' => $jwt]);

echo "<hr />";
var_dump(['Verify' => $jwt->verify($secret_key)]);

```
Output:
```
...file_path...\index.php:50:
array (size=1)
  'JWT' => 
    object(Krishna\JWT\JWT)[3]
      public 'enc' => string 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0b2tlbi50ZXN0LmNvbSIsImF1ZCI6ImFwcC50ZXN0LmNvbSIsImlhdCI6MTY0Mzg5MTc1OCwibmJmIjoxNjQzODkxNzU4LCJleHAiOjE2NzI1MzQ4MDAsIm5hbWUiOiJBbnNodSBLcmlzaG5hIiwiY2l0eSI6IkJhbmdhbG9yZSIsImp0aSI6IjZmZGZhY2JkLWU1N2MtNDI1Yy1hNDBmLWM3NjQ5YjBkNDg0MSJ9' (length=281)
      public 'sig' => string 'S�:���?zÂ8$K�=�"�/]@�+�' (length=32)
      public 'head' => 
        array (size=2)
          'alg' => string 'HS256' (length=5)
          'typ' => string 'JWT' (length=3)
      public 'body' => 
        array (size=8)
          'iss' => string 'token.test.com' (length=14)
          'aud' => string 'app.test.com' (length=12)
          'exp' => int 1672534800
          'nbf' => int 1643891758
          'iat' => int 1643891758
          'jti' => string '6fdfacbd-e57c-425c-a40f-c7649b0d4841' (length=36)
          'name' => string 'Anshu Krishna' (length=13)
          'city' => string 'Bangalore' (length=9)

...file_path...\index.php:53:
array (size=1)
  'Verify' => 
    object(Krishna\DataValidator\Returner)[26]
      public readonly mixed 'value' => boolean true
      public readonly mixed 'error' => null
      public readonly bool 'valid' => boolean true

```

Create JWT:
```php
use Krishna\JWT\Algo;
use Krishna\JWT\JWT;

$secret_key = 'your-secret';

$jwt = new JWT;

$jwt['name'] = 'AK';
$jwt['country'] = 'India';

$jwt->sign($secret_key, Algo::HS512);

echo "Token: ", $jwt, "<br><br>";

var_dump($jwt);
```
Output:
```
Token: eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQUsiLCJjb3VudHJ5IjoiSW5kaWEiLCJpYXQiOjE2NDU3NzU3MDUsIm5iZiI6MTY0NTc3NTcwNSwiaXNzIjoidGVzdC5zZXJ2ZXIiLCJleHAiOjE2NDU3NzYzMDUsImp0aSI6IjI5YWUyZTJmLTM0NGMtNDcyMy05OWMwLTMzZWEyNzRmMDMxMSJ9.pBqcBMMjeCtpzW1EarehRwsk-hBbZmZr0z1uwPii0oITsCiZ8orPIEjGgHIPC9jesd3AqoxOuCXUdA-MXhy05w

...file_path...\index.php:57:
object(Krishna\JWT\JWT)[3]
  public 'enc' => string 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQUsiLCJjb3VudHJ5IjoiSW5kaWEiLCJpYXQiOjE2NDU3NzU3MDUsIm5iZiI6MTY0NTc3NTcwNSwiaXNzIjoidGVzdC5zZXJ2ZXIiLCJleHAiOjE2NDU3NzYzMDUsImp0aSI6IjI5YWUyZTJmLTM0NGMtNDcyMy05OWMwLTMzZWEyNzRmMDMxMSJ9' (length=233)
  public 'sig' => string '���#x+i�mDj��G$[ffk�=n��҂�(��� Hƀr�ޱ����N�%�t�^��' (length=64)
  public 'head' => 
    array (size=2)
      'alg' => string 'HS512' (length=5)
      'typ' => string 'JWT' (length=3)
  public 'body' => 
    array (size=7)
      'name' => string 'AK' (length=2)
      'country' => string 'India' (length=5)
      'iat' => int 1645775705
      'nbf' => int 1645775705
      'iss' => string 'test.server' (length=11)
      'exp' => int 1645776305
      'jti' => string '29ae2e2f-344c-4723-99c0-33ea274f0311' (length=36)

```