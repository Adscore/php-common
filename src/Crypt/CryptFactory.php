<?php

namespace AdScore\Common\Crypt;

use AdScore\Common\Crypt\Symmetric\{
	OpenSSL, OpenSSLAEAD, Secretbox
};

/**
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class CryptFactory {
	
	/**
	 * Returns Crypt instance
	 * @param string $name
	 * @return OpenSSL|Secretbox
	 * @throws \InvalidArgumentException
	 */
    public static function create(string $name) {
        switch ($name) {
			case pack('v', OpenSSL::METHOD):
            case 'OpenSSL':
			case 'openssl':
                return new OpenSSL();
			case pack('v', OpenSSLAEAD::METHOD):
            case 'OpenSSLAEAD':
			case 'opensslaead':
                return new OpenSSLAEAD();
			case pack('v', Secretbox::METHOD):	
            case 'Secretbox':
			case 'secretbox':
                return new Secretbox();
            default:
                throw new \InvalidArgumentException('Unsupported crypt class');
        }
    }
	
	/**
	 * Returns Crypt instance based on payload header
	 * @param string $payload
	 * @return OpenSSL|Secretbox
	 */
	public static function createFromPayload(string $payload) {
		$header = \substr($payload, 0, 2);
		return self::create($header);
	}
	
	/**
	 * Returns Crypt instance based on algorithm/library combination ID
	 * @param int $code
	 * @return object
	 */
	public static function createFromId(int $code) {
        $name = \pack('v', $code);
		return self::create($name);
    }
    
}