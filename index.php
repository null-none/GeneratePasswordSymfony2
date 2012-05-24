<?php
// generate Token
function generateToken()
{
	$bytes = false;
	if (function_exists('openssl_random_pseudo_bytes') && 0 !== stripos(PHP_OS, 'win')) {
		$bytes = openssl_random_pseudo_bytes(32, $strong);

		if (true !== $strong) {
			$bytes = false;
		}
	}

	// let's just hope we got a good seed
	if (false === $bytes) {
		$bytes = hash('sha256', uniqid(mt_rand(), true), true);
	}

	return base_convert(bin2hex($bytes), 16, 36);
}

// encode Password
function encodePassword($raw, $salt)
{
		$algorithm = 'sha512';
		$encodeHashAsBase64 = false;
		$iterations = 1;

        if (!in_array($algorithm, hash_algos(), true)) {
            throw new \LogicException(sprintf('The algorithm "%s" is not supported.', $algorithm));
        }
        #$salt = base_convert(sha1(uniqid(mt_rand(), true)), 16, 36); 
        $salted = mergePasswordAndSalt($raw, $salt);
        $digest = hash($algorithm, $salted, true);

        // "stretch" hash
        for ($i = 1; $i < $iterations; $i++) {
            $digest = hash($algorithm, $digest.$salted, true);
        }

        return $encodeHashAsBase64 ? base64_encode($digest) : bin2hex($digest);
}


$salt = base_convert(sha1(uniqid(mt_rand(), true)), 16, 36); 
$token = generateToken();
encodePassword('password',$salt);

?>