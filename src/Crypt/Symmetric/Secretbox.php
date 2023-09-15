<?php

namespace AdScore\Common\Crypt\Symmetric;

use AdScore\Common\Crypt\Exception\{
    EncryptException, DecryptException
};

/**
 * Sodium-based symmetric cryptography
 * 
 * @author	Bartosz Derleta <bartosz@derleta.com>
 */
class Secretbox extends AbstractSymmetricCrypt {

    public const METHOD = 0x0101;

    /**
     * Generates secretbox key from password and salt
     */
    public function key(string $password, ?string $salt = null): string {
        if ($salt === null) {
            return \sodium_crypto_pwhash_str(
                $password,
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
            );
        }
        while (\strlen($salt) < SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            $salt .= $salt;
        }
        return \sodium_crypto_pwhash(
            SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            $password,
            \substr($salt, 0, SODIUM_CRYPTO_PWHASH_SALTBYTES),
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );
    }

    /**
     * Encrypt using key
     * @param string $data	Content to encrypt
     * @param string $key	Encryption key
     * @return string		Encrypted payload
     * @throws InternalError
     */
    public function encryptWithKey(string $data, string $key): string {
        $nonce = \random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        try {
            $encryptedData = \sodium_crypto_secretbox($data, $nonce, $key);
        } catch (\SodiumException $e) {
            throw new EncryptException(\ucfirst($e->getMessage()), 0, $e);
        }
        return $this->format($nonce, $encryptedData);
    }

    /**
     * Decrypt using key
     * @param string $payload	Content to decrypt
     * @param string $key       Decryption key
     * @return string           Decrypted payload
     * @throws DecryptError
     * @throws InternalError
     */
    public function decryptWithKey(string $payload, string $key): string {
        [
            'method' => $method,
            'iv' => $iv,
            'data' => $data
            ] = $this->parse($payload, ['iv' => SODIUM_CRYPTO_SECRETBOX_NONCEBYTES]);
        if ($method !== self::METHOD) {
            throw new DecryptException('Unrecognized payload', 1);
        }
        try {
            $decryptedData = \sodium_crypto_secretbox_open($data, $iv, $key);
        } catch (\SodiumException $e) {
            throw new DecryptException(\ucfirst($e->getMessage()), 0, $e);
        }
        if ($decryptedData === false) {
            throw new DecryptException('Not a valid payload', 2);
        }
        return $decryptedData;
    }

}
