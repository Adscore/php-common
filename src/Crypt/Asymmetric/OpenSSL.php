<?php namespace AdScore\Common\Crypt\Asymmetric;

use AdScore\Common\Crypt\Exception\KeyException;
use AdScore\Common\Signature\Exception\VerifyException;
use AdScore\Common\Crypt\OpenSSLSafeCallTrait;
use InvalidArgumentException;
use RuntimeException;

class OpenSSL extends AbstractAsymmetricCrypt {
	
    use OpenSSLSafeCallTrait;
    
    protected string $algo = 'sha256';
    protected int $options = OPENSSL_RAW_DATA;

    public function __construct(string $algo = 'sha256') {
        if (!\in_array($algo, \openssl_get_md_methods(true))) {
            throw new InvalidArgumentException('Invalid hash method "' . $algo . '"');
        }
        $this->algo = $algo;
    }
    
    /**
     * Verify signature
     * @param string $data      The string of data used to generate the signature previously 
     * @param string $signature A raw binary string
     * @param string $publicKey OpenSSL asymmetric key
     * @return bool
     * @throws VerifyException
     */
    public function verify(string $data, string $signature, string $publicKey): bool {
        $result = self::safeCall('verify', $data, $signature, $publicKey, $this->algo);
        if ($result === -1) {
            throw new VerifyException('Signature verification error');
        }
        return ($result === 1);
    }
    
    /**
     * Generate signature
     * @param string $data          The string of data you wish to sign 
     * @param string $privateKey    OpenSSL asymmetric key
     * @return string               Computed signature
     */
    public function sign(string $data, string $privateKey): string {
        $signature = '';
        $privateKeyPem = self::expandPem($privateKey);
        self::safeCall('sign', $data, $signature, $privateKeyPem, $this->algo);
    }
    
	/**
	 * Create EC keypair
	 * 
	 * @param $curveName	Curve name
	 * @return				Compacted private key
	 */
	public static function createEcPrivateKey(string $curveName = 'prime256v1') : string {
		if (!\in_array($curveName, \openssl_get_curve_names())) {
			throw new InvalidArgumentException('Unsupported curve type "' . $curveName . '"');
        }
		$pkeyArgs = [
			'curve_name' => $curveName,
			'private_key_type' => OPENSSL_KEYTYPE_EC
		];
        try {
            $pkey = self::safeCall('pkey_new', $pkeyArgs);
            $data = null;
            self::safeCall('pkey_export', $pkey, $data);
            \openssl_free_key($pkey);
            return self::compactPem($data);
        } catch (RuntimeException $e) {
            throw new KeyException('Cannot create EC private key', 0, $e);
        }
	}
	
	/**
	 * Retrieve public key in PEM format from compacted private key
	 * 
	 * @param $data	Compacted key
	 * @return		Public key in PEM format
	 */
	public static function getPublicKeyPem(string $data) : string {
		try {
            $expandedPem = self::expandPem($data);
            $pkey = self::safeCall('pkey_get_private', $expandedPem);
            try {
                $details = self::safeCall('pkey_get_details', $pkey);
            } finally {
                \openssl_free_key($pkey);
            }
            return $details['key'];
        } catch (RuntimeException $e) {
            throw new KeyException('Cannot retrieve public key', 0, $e);
        }
	}
	
}
