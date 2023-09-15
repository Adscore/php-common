<?php

namespace AdScore\Common\Crypt\Symmetric;

use AdScore\Common\Crypt\Exception\ParseException;

/**
 * Symmetric cryptography abstraction
 * 
 * @author	Bartosz Derleta <bartosz@derleta.com>
 */
abstract class AbstractSymmetricCrypt {

    public const METHOD_SIZE = 2;
    
    /**
     * Encrypt, for example, URL list for zone
     * 
     * @param string $data			Content to encrypt
     * @param string $password		Content password (zones.request_pass)
     * @param string|null $salt	 	Content password salt (zones.request_key)
     * @return						Encrypted payload
     */
    public function encrypt(string $data, string $password, ?string $salt = null): string {
        $key = $this->key($password, $salt);
        return $this->encryptWithKey($data, $key);
    }

    /**
     * Encrypt using key
     * 
     * @param string $data			Content to encrypt
     * @param string $key			Encryption key
     * @return string				Encrypted payload
     */
    abstract public function encryptWithKey(string $data, string $key): string;

    /**
     * Decrypt, for example, URL list for zone
     * 
     * @param 	$data		Content to decrypt
     * @param	$password	Content password (zones.request_pass)
     * @param	$salt	 	Content password salt (zones.request_key)
     * @return				Decrypted payload
     */
    public function decrypt(string $data, string $password, string $salt): string {
        $key = $this->key($password, $salt);
        return $this->decryptWithKey($data, $key);
    }

    /**
     * Decrypt using key
     * 
     * @param string $data			Content to decrypt
     * @param string $key			Decryption key
     * @return string				Decrypted payload
     */
    abstract public function decryptWithKey(string $data, string $key): string;

    /**
     * Derive a key from a password and optional salt
     * 
     * @param string $password		Password
     * @param string|null $salt		Salt
     * @return string				Key
     */
    abstract public function key(string $password, ?string $salt = null): string;

    /**
     * Format struct mark, nonce/iv and data into payload
     */
    protected function format(string ...$items): string {
        return \pack('v', static::METHOD) . \join('', $items);
    }

    /**
     * Retrieve struct mark, nonce/iv and data from payload
     */
    protected function parse(string $payload, array $lengths): array {
        if (\strlen($payload) < (self::METHOD_SIZE + \array_sum($lengths))) {
            throw new ParseException('Premature data end');
        }
        $result = \unpack('vmethod', \substr($payload, 0, $pos = self::METHOD_SIZE));
        foreach ($lengths as $k => $length) {
            $result[$k] = \substr($payload, $pos, $length);
            $pos += $length;
        }
        $result['data'] = \substr($payload, $pos);
        return $result;
    }

}
