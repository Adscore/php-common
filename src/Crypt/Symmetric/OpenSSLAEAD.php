<?php

namespace AdScore\Common\Crypt\Symmetric;

use AdScore\Common\Crypt\Exception\{
    EncryptException, DecryptException
};
use RuntimeException;

/**
 * OpenSSL-based symmetric cryptography
 *
 * @author	Bartosz Derleta <bartosz@derleta.com>
 */
class OpenSSLAEAD extends OpenSSL {

    public const METHOD = 0x0201;

    protected $tagLength = 16;

    public function __construct() {
        parent::__construct('aes-256-gcm');
    }

    /**
     * Encrypt using key
     * 
     * @param string $data			Content to encrypt
     * @param string $key			Encryption key
     * @param string $aad           Additional authentication data
     * @return string				Encrypted payload
     * @throws EncryptError
     */
    public function encryptWithKey(string $data, string $key, string $aad = ''): string {
        try {
            $iv = $this->getIv();
            $tag = null;
            $encryptedData = $this->safeCall('encrypt', $data, $this->method, $key, $this->options, $iv, $tag, $aad, $this->tagLength);
            return $this->format($iv, $tag, $encryptedData);
        } catch (RuntimeException $e) {
            throw new EncryptException($e->getMessage(), 0, $e);
        }
    }

    /**
     * Decrypt using key
     * 
     * @param string $payload       Content to decrypt
     * @param string $key           Decryption key
     * @param string $aad           Additional authentication data
     * @return string               Decrypted payload
     * @throws DecryptError
     */
    public function decryptWithKey(string $payload, string $key, string $aad = ''): string {
        [
            'method' => $method,
            'iv' => $iv,
            'tag' => $tag,
            'data' => $data
        ] = $this->parse($payload, [
            'iv' => \openssl_cipher_iv_length($this->method),
            'tag' => $this->tagLength
        ]);
        if ($method !== self::METHOD) {
            throw new DecryptException('Unrecognized payload', 1);
        }
        try {
            return $this->safeCall('decrypt', $data, $this->method, $key, $this->options, $iv, $tag, $aad);
        } catch (RuntimeException $e) {
            throw new DecryptException($e->getMessage(), 0, $e);
        }
    }

}
