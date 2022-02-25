<?php
namespace Krishna\JWT;
use Krishna\DataValidator\Returner;

enum Algo:string {
	case HS256 = 'HS256';
	case HS384 = 'HS384';
	case HS512 = 'HS512';
	
	case RS256 = 'RS256';
	case RS384 = 'RS384';
	case RS512 = 'RS512';
	
	public function sign(string $plain, string $key) : ?string {
		$class = __NAMESPACE__ . "\\AlgoHandler\\{$this->value}";
		if(class_exists($class) && is_subclass_of($class, AlgoInterface::class)) {
			return $class::sign($plain, $key);
		}
		return null;
	}
	public function verify(string $enc, string $sig, string $key) : Returner {
		$class = __NAMESPACE__ . "\\AlgoHandler\\{$this->value}";
		if(class_exists($class) && is_subclass_of($class, AlgoInterface::class)) {
			if($class::verify($enc, $sig, $key)) {
				return Returner::valid();
			}
			return Returner::invalid('Invalid signature');
		}
		return Returner::invalid('Algoritm handler missing');
	}
}