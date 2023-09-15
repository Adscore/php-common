<?php

namespace AdScore\Common\Crypt\Symmetric;

use InvalidArgumentException;
use RuntimeException;
use AdScore\Common\Crypt\Exception\{
    EncryptException, DecryptException
};
use AdScore\Common\Crypt\OpenSSLSafeCallTrait;

/**
 * OpenSSL-based symmetric cryptography
 *
 * @author	Bartosz Derleta <bartosz@derleta.com>
 */
class OpenSSL extends AbstractSymmetricCrypt {

    use OpenSSLSafeCallTrait;
    
    public const METHOD = 0x0200;

    protected string $method = 'aes-256-cbc';
    protected string $algo = 'sha256';
    protected int $options = OPENSSL_RAW_DATA;

    public function __construct(string $method = 'aes-256-cbc', string $algo = 'sha256') {
        if (!\in_array($method, \openssl_get_cipher_methods())) {
            throw new InvalidArgumentException('Invalid cipher method "' . $method . '"');
        }
        $this->method = $method;
        if (!\in_array($algo, \hash_hmac_algos())) {
            throw new InvalidArgumentException('Invalid hash method "' . $algo . '"');
        }
        $this->algo = $algo;
    }

    /**
     * Generates secretbox key from password and salt
     * @param string $password
     * @param string|null $salt
     * @return string
     */
    public function key(string $password, ?string $salt = null): string {
        if ($salt === null) {
            return \hash($this->algo, $password, true);
        }
        return \hash_hmac($this->algo, $password, $salt, true);
    }

    /**
     * Create initialization vector
     * @return string
     */
    protected function getIv(): string {
        $ivLength = \openssl_cipher_iv_length($this->method);
        return self::safeCall('random_pseudo_bytes', $ivLength);
    }

    /**
     * Encrypt using key
     * 
     * @param string $data			Content to encrypt
     * @param string $key			Encryption key
     * @return string				Encrypted payload
     * @throws EncryptError
     */
    public function encryptWithKey(string $data, string $key): string {
        try {
            $iv = $this->getIv();
            $encryptedData = self::safeCall('encrypt', $data, $this->method, $key, $this->options, $iv);
            return $this->format($iv, $encryptedData);
        } catch (RuntimeException $e) {
            throw new EncryptException($e->getMessage(), 0, $e);
        }
    }

    /**
     * Decrypt using key
     * 
     * @param string $payload       Content to decrypt
     * @param string $key           Decryption key
     * @return string               Decrypted payload
     * @throws DecryptError
     */
    public function decryptWithKey(string $payload, string $key): string {
        [
            'method' => $method,
            'iv' => $iv,
            'data' => $data
        ] = $this->parse($payload, ['iv' => \openssl_cipher_iv_length($this->method)]);
        if ($method !== self::METHOD) {
            throw new DecryptException('Unrecognized payload', 1);
        }
        try {
            return self::safeCall('decrypt', $data, $this->method, $key, $this->options, $iv);
        } catch (RuntimeException $e) {
            throw new DecryptException($e->getMessage(), 0, $e);
        }
    }

}
